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

RSpec.describe Documents::OAuth::RefreshTokenService,
               with_settings: { collaborative_editing_hocuspocus_secret: "test_secret_for_encryption" } do
  subject(:service_call) do
    described_class.new(user:, document:, project:, previous_token:).call
  end

  let(:project) { create(:project) }
  let(:document) { create(:document, project:) }
  let(:role) { create(:project_role, permissions: %i[view_documents]) }
  let(:user) { create(:user, member_with_roles: { project => role }) }

  let(:previous_token_result) do
    Documents::OAuth::TokenWithMetadataService.new(user:, document:, project:).call.result
  end
  let(:previous_token) { previous_token_result[:encrypted_token] }
  let(:previous_access_token) { access_token_for(previous_token) }

  def decrypt_payload(encrypted_token)
    JSON.parse(Documents::OAuth::DecryptTokenService.new(token: encrypted_token).call.result)
  end

  def access_token_for(encrypted_token)
    Doorkeeper::AccessToken.by_token(decrypt_payload(encrypted_token)["oauth_token"])
  end

  def encrypt(payload)
    Documents::OAuth::EncryptTokenService.new(token: payload.to_json).call.result
  end

  shared_examples "rejects the previous token" do
    it "fails with an invalid token error" do
      expect(service_call).to be_failure
      expect(service_call.includes_error?(:token, :invalid)).to be(true)
      expect(service_call.message).to eq(I18n.t("documents.collaboration_token.errors.invalid_previous_token"))
    end

    it "neither revokes nor creates a token" do
      previous_token

      expect { service_call }.not_to change(Doorkeeper::AccessToken, :count)
      expect(Doorkeeper::AccessToken.where.not(revoked_at: nil)).to be_empty
    end
  end

  describe "#call" do
    context "with a valid previous token", freeze_time: DateTime.parse("2025-01-04T09:00:00Z") do
      it "returns a new collaboration token" do
        expect(service_call).to be_success
        expect(service_call.result[:encrypted_token]).not_to eq(previous_token)
        expect(service_call.result[:expires_in_seconds]).to eq(5.minutes.to_i)

        payload = decrypt_payload(service_call.result[:encrypted_token])
        expect(payload["resource_url"]).to eq(previous_token_result[:resource_url])
        expect(payload["expires_at"]).to eq("2025-01-04T09:05:00Z")
      end

      it "issues a new access token for the user" do
        previous_token

        expect { service_call }.to change(Doorkeeper::AccessToken, :count).by(1)

        new_access_token = access_token_for(service_call.result[:encrypted_token])
        expect(new_access_token.resource_owner_id).to eq(user.id)
        expect(new_access_token).not_to eq(previous_access_token)
        expect(new_access_token.revoked_at).to be_nil
      end

      it "revokes the previous access token after the grace period" do
        service_call

        previous_access_token.reload
        expect(previous_access_token.revoked_at).to eq(Time.current + described_class::REVOCATION_GRACE_PERIOD)
        expect(previous_access_token).not_to be_revoked

        travel(described_class::REVOCATION_GRACE_PERIOD + 1.second)

        expect(previous_access_token).to be_revoked
      end
    end

    context "when the previous access token is already revoked" do
      let(:earlier) { 1.minute.ago.change(usec: 0) }

      before do
        previous_access_token.update_column(:revoked_at, earlier)
      end

      it "does not postpone the revocation" do
        expect(service_call).to be_success
        expect(previous_access_token.reload.revoked_at).to eq(earlier)
      end
    end

    context "when the previous token is expired" do
      before do
        previous_token
        travel 10.minutes
      end

      it "still refreshes it" do
        expect(service_call).to be_success
        expect(previous_access_token.reload.revoked_at).to be_present
      end
    end

    context "with a garbage token" do
      let(:previous_token) { "garbage" }

      it_behaves_like "rejects the previous token"
    end

    context "with a tampered token" do
      let(:previous_token) { previous_token_result[:encrypted_token].reverse }

      it_behaves_like "rejects the previous token"
    end

    context "with an encrypted payload that is not a JSON object" do
      let(:previous_token) { Documents::OAuth::EncryptTokenService.new(token: "[1, 2]").call.result }

      it_behaves_like "rejects the previous token"
    end

    context "with a token for another document" do
      let(:other_document) { create(:document, project:) }
      let(:previous_token) do
        Documents::OAuth::TokenWithMetadataService
          .new(user:, document: other_document, project:)
          .call
          .result[:encrypted_token]
      end

      it_behaves_like "rejects the previous token"
    end

    context "with a token belonging to another user" do
      let(:other_user) { create(:user, member_with_roles: { project => role }) }
      let(:previous_token) do
        Documents::OAuth::TokenWithMetadataService
          .new(user: other_user, document:, project:)
          .call
          .result[:encrypted_token]
      end

      it_behaves_like "rejects the previous token"
    end

    context "with a token whose OAuth token belongs to another OAuth application" do
      let(:foreign_access_token) { create(:oauth_access_token, resource_owner: user) }
      let(:previous_token) do
        encrypt(resource_url: previous_token_result[:resource_url],
                oauth_token: foreign_access_token.plaintext_token,
                expires_at: 5.minutes.from_now.iso8601,
                readonly: true)
      end

      it_behaves_like "rejects the previous token"
    end

    context "with a token whose OAuth token does not exist" do
      let(:previous_token) do
        encrypt(resource_url: previous_token_result[:resource_url],
                oauth_token: "does-not-exist",
                expires_at: 5.minutes.from_now.iso8601,
                readonly: true)
      end

      it_behaves_like "rejects the previous token"
    end

    context "when minting the new token fails" do
      before do
        previous_token

        allow(Documents::OAuth::EncryptTokenService)
          .to receive(:new)
          .and_return(instance_double(Documents::OAuth::EncryptTokenService,
                                      call: ServiceResult.failure(errors: "Encryption failed")))
        allow(Rails.logger).to receive(:error)
      end

      it "fails without an invalid token error" do
        expect(service_call).to be_failure
        expect(service_call.includes_error?(:token, :invalid)).to be(false)
      end

      it "neither revokes the previous token nor keeps a new one" do
        expect { service_call }.not_to change(Doorkeeper::AccessToken, :count)
        expect(previous_access_token.reload.revoked_at).to be_nil
      end
    end
  end
end
