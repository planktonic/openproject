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

RSpec.describe "API v3 document collaboration token resource" do
  include Rack::Test::Methods
  include API::V3::Utilities::PathHelper

  include_context "with a collaboration token endpoint setup"

  let(:path) { api_v3_paths.document_collaboration_token(document.id) }
  let(:request_body) { nil }

  describe "POST /api/v3/documents/:id/collaboration_token" do
    it_behaves_like "a guarded collaboration token endpoint"

    context "when logged in with the view_documents permission",
            freeze_time: DateTime.parse("2025-01-04T09:00:00Z") do
      let(:response_body) { JSON.parse(last_response.body) }
      let(:expected_document_name) { "http://#{Setting.host_name}#{api_v3_paths.document(document.id)}" }

      before do
        login_as(current_user)

        post_collaboration_token_request
      end

      it "responds with 201 and a collaboration token" do
        expect(last_response).to have_http_status(:created)

        expect(response_body).to include(
          "_type" => "CollaborationToken",
          "documentName" => expected_document_name,
          "expiresAt" => "2025-01-04T09:05:00Z",
          "expiresInSeconds" => 300
        )
      end

      it "returns an encrypted token for the document and the user" do
        payload = decrypt_collaboration_token(response_body["token"])

        expect(payload["resource_url"]).to eq(expected_document_name)
        expect(payload["expires_at"]).to eq("2025-01-04T09:05:00Z")

        access_token = Doorkeeper::AccessToken.by_token(payload["oauth_token"])
        expect(access_token.resource_owner_id).to eq(current_user.id)
        expect(access_token.expires_in).to eq(5.minutes.to_i)
        expect(Documents::OAuth::EnsureApplicationService.collaboration_token?(access_token)).to be(true)
      end

      it "does not expose the plain OAuth token" do
        payload = decrypt_collaboration_token(response_body["token"])

        expect(last_response.body).not_to include(payload["oauth_token"])
      end

      it "links the document, the refresh action and the collaboration server" do
        expect(last_response.body)
          .to be_json_eql(api_v3_paths.document(document.id).to_json)
          .at_path("_links/document/href")
        expect(last_response.body)
          .to be_json_eql(api_v3_paths.document_collaboration_token_refresh(document.id).to_json)
          .at_path("_links/refresh/href")
        expect(last_response.body)
          .to be_json_eql("post".to_json)
          .at_path("_links/refresh/method")
        expect(last_response.body)
          .to be_json_eql(hocuspocus_url.to_json)
          .at_path("_links/collaborationServer/href")
        expect(last_response.body).not_to have_json_path("_links/self")
      end
    end

    context "when creating the token fails" do
      before do
        login_as(current_user)

        allow(Documents::OAuth::TokenWithMetadataService)
          .to receive(:new)
          .and_return(instance_double(Documents::OAuth::TokenWithMetadataService,
                                      call: ServiceResult.failure(errors: "Something went wrong")))

        post_collaboration_token_request
      end

      it "responds with 500" do
        expect(last_response).to have_http_status(:internal_server_error)
        expect(last_response.body).not_to include("Something went wrong")
      end
    end
  end
end
