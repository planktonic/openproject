# frozen_string_literal: true

#-- copyright
# OpenProject is an open source project management software.
# Copyright (C) the OpenProject GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version 3.
#
# OpenProject is a fork of ChiliProject, which is a fork of Redmine. The copyright follows:
# Copyright (C) 2006-2013 Jean-Philippe Lang
# Copyright (C) 2010-2013 the ChiliProject Team
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# See COPYRIGHT and LICENSE files for more details.
#++

require "spec_helper"
require "rack/test"
require_relative "../../../../support/shared/collaboration_token_endpoint"

RSpec.describe "API v3 document collaboration token refresh resource" do
  include Rack::Test::Methods
  include API::V3::Utilities::PathHelper

  include_context "with a collaboration token endpoint setup"

  let(:path) { api_v3_paths.document_collaboration_token_refresh(document.id) }
  let(:previous_token) { mint_previous_token(user: current_user, document:) }
  let(:request_body) { { token: previous_token } }
  let(:previous_access_token) do
    Doorkeeper::AccessToken.by_token(decrypt_collaboration_token(previous_token)["oauth_token"])
  end

  def mint_previous_token(user:, document:)
    Documents::OAuth::TokenWithMetadataService
      .new(user:, document:, project: document.project)
      .call
      .result[:encrypted_token]
  end

  describe "POST /api/v3/documents/:id/collaboration_token/refresh" do
    it_behaves_like "a guarded collaboration token endpoint"

    context "when logged in" do
      let(:response_body) { JSON.parse(last_response.body) }

      before do
        login_as(current_user)
      end

      context "with a valid previous token", freeze_time: DateTime.parse("2025-01-04T09:00:00Z") do
        let(:previous_oauth_token) { decrypt_collaboration_token(previous_token)["oauth_token"] }

        before do
          previous_token

          post_collaboration_token_request
        end

        it "responds with 201 and a new collaboration token" do
          expect(last_response).to have_http_status(:created)
          expect(last_response.headers["Cache-Control"]).to eq("no-store")

          expect(response_body).to include("_type" => "CollaborationToken",
                                           "expiresAt" => "2025-01-04T09:05:00Z",
                                           "expiresInSeconds" => 300)
          expect(response_body["token"]).not_to eq(previous_token)

          payload = decrypt_collaboration_token(response_body["token"])
          expect(payload["oauth_token"]).not_to eq(previous_oauth_token)
          expect(payload["resource_url"]).to eq(response_body["documentName"])
        end

        it "revokes the previous OAuth token after the grace period" do
          expect(previous_access_token.revoked_at)
            .to eq(Time.current + Documents::OAuth::RefreshTokenService::REVOCATION_GRACE_PERIOD)
        end

        it "keeps the previous OAuth token usable during the grace period only" do
          header "Authorization", "Bearer #{previous_oauth_token}"

          get api_v3_paths.document(document.id)
          expect(last_response).to have_http_status(:ok)

          travel(Documents::OAuth::RefreshTokenService::REVOCATION_GRACE_PERIOD + 1.second)

          get api_v3_paths.document(document.id)
          expect(last_response).to have_http_status(:unauthorized)
        end
      end

      context "with an expired previous token" do
        before do
          previous_token
          travel 10.minutes

          post_collaboration_token_request
        end

        it "responds with 201" do
          expect(last_response).to have_http_status(:created)
          expect(previous_access_token.revoked_at).to be_present
        end
      end

      context "without a token" do
        let(:request_body) { {} }

        it "responds with 400" do
          post_collaboration_token_request

          expect(last_response).to have_http_status(:bad_request)
          expect(Doorkeeper::AccessToken.count).to eq(0)
        end
      end

      shared_examples "rejects the previous token" do
        it "responds with 422 and neither revokes nor creates a token" do
          previous_token

          expect { post_collaboration_token_request }.not_to change(Doorkeeper::AccessToken, :count)

          expect(last_response).to have_http_status(422)
          expect(last_response.body)
            .to be_json_eql("urn:openproject-org:api:v3:errors:UnprocessableContent".to_json)
            .at_path("errorIdentifier")
          expect(last_response.body)
            .to be_json_eql(I18n.t("documents.collaboration_token.errors.invalid_previous_token").to_json)
            .at_path("message")
          expect(Doorkeeper::AccessToken.where.not(revoked_at: nil)).to be_empty
        end
      end

      context "with a garbage token" do
        let(:previous_token) { "garbage" }

        it_behaves_like "rejects the previous token"
      end

      context "with a tampered token" do
        let(:previous_token) { mint_previous_token(user: current_user, document:).reverse }

        it_behaves_like "rejects the previous token"
      end

      context "with a token for another document" do
        let(:previous_token) { mint_previous_token(user: current_user, document: create(:document, project:)) }

        it_behaves_like "rejects the previous token"
      end

      context "with a token belonging to another user" do
        let(:other_user) { create(:user, member_with_roles: { project => role }) }
        let(:previous_token) { mint_previous_token(user: other_user, document:) }

        it_behaves_like "rejects the previous token"
      end

      context "with a token whose OAuth token lacks the collaboration scope" do
        let(:previous_token) do
          payload = {
            resource_url: "http://#{Setting.host_name}#{api_v3_paths.document(document.id)}",
            oauth_token: create(:oauth_access_token, resource_owner: current_user).plaintext_token,
            expires_at: 5.minutes.from_now.iso8601,
            readonly: true
          }

          Documents::OAuth::EncryptTokenService.new(token: payload.to_json).call.result
        end

        it_behaves_like "rejects the previous token"
      end
    end
  end
end
