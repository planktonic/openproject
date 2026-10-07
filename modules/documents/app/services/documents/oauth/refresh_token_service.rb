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

module Documents
  module OAuth
    ##
    # Exchanges a previously issued collaboration token for a new one.
    #
    # The caller is authorized by their own credential; the previous token only identifies
    # which Doorkeeper access token to revoke. It may therefore already be expired.
    #
    # The previous access token is revoked with a grace period, so the collaboration server
    # can keep using it until the client has handed the new token over.
    class RefreshTokenService < BaseServices::BaseCallable
      REVOCATION_GRACE_PERIOD = 30.seconds

      attr_reader :user, :document, :project, :previous_token

      def initialize(user:, document:, project:, previous_token:)
        super()

        @user = user
        @document = document
        @project = project
        @previous_token = previous_token
      end

      def perform
        previous_access_token = find_previous_access_token
        return invalid_previous_token_result if previous_access_token.nil?

        mint_and_revoke(previous_access_token)
      end

      private

      # Nothing is revoked (and no new token is kept) if minting the new token fails.
      # The cause of such a failure is logged by the TokenWithMetadataService already.
      def mint_and_revoke(previous_access_token)
        token_result = nil

        ::Doorkeeper::AccessToken.transaction do
          token_result = token_with_metadata_service.call
          raise ActiveRecord::Rollback if token_result.failure?

          revoke_with_grace_period(previous_access_token)
        end

        if token_result.success?
          token_result
        else
          ServiceResult.failure(message: I18n.t("api_v3.errors.code_500"))
        end
      end

      def find_previous_access_token
        payload = decrypted_payload
        return if payload.nil?
        return if payload["resource_url"] != token_with_metadata_service.resource_url

        access_token = ::Doorkeeper::AccessToken.by_token(payload["oauth_token"])
        return unless access_token&.includes_scope?(COLLABORATION_SCOPE)
        return if access_token.resource_owner_id != user.id

        access_token
      end

      def decrypted_payload
        decrypt_result = DecryptTokenService.new(token: previous_token).call
        return unless decrypt_result.success?

        payload = JSON.parse(decrypt_result.result)
        payload if payload.is_a?(Hash)
      rescue JSON::ParserError
        nil
      end

      # Doorkeeper considers a token revoked once `revoked_at <= now`, so a value in the
      # future keeps it valid until then. An earlier revocation is never postponed.
      def revoke_with_grace_period(access_token)
        revoked_at = [access_token.revoked_at, REVOCATION_GRACE_PERIOD.from_now].compact.min

        access_token.update_column(:revoked_at, revoked_at)
      end

      def token_with_metadata_service
        @token_with_metadata_service ||= TokenWithMetadataService.new(user:, document:, project:)
      end

      def invalid_previous_token_result
        ServiceResult
          .failure(message: I18n.t("documents.collaboration_token.errors.invalid_previous_token"))
          .tap { |result| result.errors.add(:token, :invalid) }
      end
    end
  end
end
