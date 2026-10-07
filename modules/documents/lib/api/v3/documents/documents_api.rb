# frozen_string_literal: true

require "base64"
require "json"

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

module API
  module V3
    module Documents
      class DocumentsAPI < ::API::OpenProjectAPI
        helpers ::API::Utilities::UrlPropsParsingHelper

        resources :documents do
          get do
            query = ParamsToQueryService
                    .new(Document, current_user)
                    .call(params)

            if query.valid?
              DocumentCollectionRepresenter.new(query.results,
                                                self_link: api_v3_paths.documents,
                                                page: to_i_or_nil(params[:offset]),
                                                per_page: resolve_page_size(params[:pageSize]),
                                                current_user:)
            else
              raise_query_errors query
            end
          end

          route_param :id, type: Integer, desc: "Document ID" do
            helpers do
              def document
                Document.visible.find(params[:id])
              end
            end

            route_setting :oauth_scopes, [::Documents::OAuth::COLLABORATION_SCOPE]
            get do
              ::API::V3::Documents::DocumentRepresenter.new(document,
                                                            current_user:,
                                                            embed_links: true)
            end

            route_setting :oauth_scopes, [::Documents::OAuth::COLLABORATION_SCOPE]
            patch do
              doc = document
              request_body = JSON.parse(request.body.read)

              result = ::Documents::UpdateService
                .new(user: current_user, model: doc)
                .call(request_body)

              if result.success?
                ::API::V3::Documents::DocumentRepresenter.new(doc,
                                                              current_user:,
                                                              embed_links: true)
              else
                fail ::API::Errors::ErrorBase.create_and_merge_errors(doc.errors)
              end
            end

            namespace :collaboration_token do
              helpers do
                def collaboration_document
                  @collaboration_document ||= document
                end

                def authorize_collaboration_token_request
                  authorize_in_project(:view_documents, project: collaboration_document.project)
                  ensure_collaboration_available
                end

                def ensure_collaboration_available
                  error_key = collaboration_unavailable_reason
                  return if error_key.nil?

                  raise ::API::Errors::UnprocessableContent.new(
                    I18n.t("documents.collaboration_token.errors.#{error_key}")
                  )
                end

                def collaboration_unavailable_reason
                  if !collaboration_document.collaborative?
                    :not_collaborative
                  elsif !Setting.real_time_text_collaboration_enabled?
                    :collaboration_disabled
                  elsif Setting.collaborative_editing_hocuspocus_url.blank? ||
                        Setting.collaborative_editing_hocuspocus_secret.blank?
                    :server_not_configured
                  end
                end

                def collaboration_token_response(token_result)
                  header "Cache-Control", "no-store"
                  status 201

                  CollaborationTokenRepresenter.new(
                    CollaborationTokenRepresenter::CollaborationToken.from_token_result(collaboration_document,
                                                                                        token_result),
                    current_user:
                  )
                end

                def fail_token_creation
                  raise ::API::Errors::SafeInternalError.new(I18n.t("api_v3.errors.code_500"))
                end
              end

              after_validation do
                authorize_collaboration_token_request
              end

              post do
                result = ::Documents::OAuth::TokenWithMetadataService
                  .new(user: current_user, document: collaboration_document, project: collaboration_document.project)
                  .call

                fail_token_creation if result.failure?

                collaboration_token_response(result.result)
              end

              namespace :refresh do
                params do
                  requires :token, type: String, desc: "The previously issued collaboration token"
                end

                post do
                  result = ::Documents::OAuth::RefreshTokenService
                    .new(user: current_user,
                         document: collaboration_document,
                         project: collaboration_document.project,
                         previous_token: declared_params[:token])
                    .call

                  if result.success?
                    collaboration_token_response(result.result)
                  elsif result.includes_error?(:token, :invalid)
                    raise ::API::Errors::UnprocessableContent.new(result.message)
                  else
                    fail_token_creation
                  end
                end
              end
            end

            mount ::API::V3::Attachments::AttachmentsByDocumentAPI
          end
        end
      end
    end
  end
end
