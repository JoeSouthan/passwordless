# frozen_string_literal: true

module Passwordless
  # Helpers to work with Passwordless sessions from controllers
  module ControllerHelpers
    extend ActiveSupport::Concern

    included do
      # Aliases {ModelHelpers#current_authenticatable} into the controllers and views
      # @param authenticatable_class [ActiveRecord::Base] Authenticatable resource eg: User
      # @see ModelHelpers#current_authenticatable
      def self.passwordless_for(authenticatable_class)
        @@authenticatable_class = authenticatable_class.base_class
        @@authenticatable_class_underscored = authenticatable_class.base_class.to_s.parameterize.underscore
        current_resource_name = :"current_#{@@authenticatable_class_underscored}"

        unless method_defined?(current_resource_name)
          alias_method current_resource_name, :current_authenticatable
          helper_method current_resource_name
        end
      end
    end

    # Returns the {Session} (if set) from the session.
    # @return [Session, nil]
    def current_passwordless_session
      @current_passwordless_session ||= Passwordless::Session.find_by(id: session[session_key])
    end

    # Returns the Authenticatable model from the current {Session} (if set).
    # @return [ActiveRecord::Base, nil]
    def current_authenticatable
      return unless current_passwordless_session&.valid_session?
      @current_authenticatable ||= current_passwordless_session.authenticatable
    end

    # Build a new Passwordless::Session from an _authenticatable_ record.
    # Set's `user_agent` and `remote_addr` from Rails' `request`.
    # @param authenticatable [ActiveRecord::Base] Instance of an
    #   authenticatable Rails model
    # @return [Session] the new Session object
    # @see ModelHelpers#passwordless_with
    def build_passwordless_session(authenticatable)
      Session.new.tap do |us|
        us.remote_addr = request.remote_addr
        us.user_agent = request.env["HTTP_USER_AGENT"]
        us.authenticatable = authenticatable
      end
    end

    # @deprecated Use {ControllerHelpers#current_authenticatable}
    # Attempts to authenticate a record using cookies. Looks for a cookie corresponding to
    # the _authenticatable_class_. If found try to find it in the database.
    # Will attempt to authenticate from the session instead
    # @param authenticatable_class [ActiveRecord::Base] any Model connected to
    #   passwordless. (e.g - _User_ or _Admin_).
    # @return [ActiveRecord::Base|nil] an instance of Model found by id stored
    #   in cookies.encrypted or nil if nothing is found.
    # @see ModelHelpers#passwordless_with
    def authenticate_by_cookie(authenticatable_class)
      key = cookie_name(authenticatable_class)
      authenticatable_id = cookies.encrypted[key]

      return authenticatable_class.find_by(id: authenticatable_id) if authenticatable_id
      current_authenticatable
    end
    deprecate :authenticate_by_cookie, deprecator: CookieDeprecation

    # Signs in user by assigning the [Passwordless::Session] id to the session.
    # Will sign out any user currently logged in.
    # @param record [Passwordless::Session, ActiveRecord::Base]
    #   Instance of session to sign in, eg: User or Passwordless::Session
    # @return [ActiveRecord::Base] the authenticatable that is present on the record.
    def sign_in(record)
      passwordless_session = if record.is_a?(Passwordless::Session)
        record
      else
        build_passwordless_session(record).tap { |s| s.save! }
      end

      sign_out

      raise Errors::SessionTimedOutError if passwordless_session.timed_out?
      passwordless_session.claim! if Passwordless.restrict_token_reuse

      session.update(session_key => passwordless_session.id)

      passwordless_session.authenticatable
    end

    # Signs out user by deleting their session id or encrypted cookie.
    # @param authenticatable_class [ActiveRecord::Base, nil]
    # @return [boolean] Always true
    def sign_out(authenticatable_class = nil)
      if authenticatable_class
        key = cookie_name(authenticatable_class)
        cookies.encrypted.permanent[key] = {value: nil}
        cookies.delete(key)
      end

      session.delete session_key
      true
    end

    # Saves request.original_url as the redirect location for a
    # passwordless Model.
    # @param (see #authenticate_by_cookie)
    # @return [String] the redirect url that was just saved.
    def save_passwordless_redirect_location!(_authenticatable_class = nil)
      session[redirect_session_key] = request.original_url
    end

    # Resets the redirect_location to root_path by deleting the redirect_url
    # from session.
    # @param (see #authenticate_by_cookie)
    # @return [String, nil] the redirect url that was just deleted,
    #   or nil if no url found for given Model.
    def reset_passwordless_redirect_location!(_authenticatable_class = nil)
      session.delete redirect_session_key
    end

    private

    def session_key
      :"passwordless_session_id_for_#{@@authenticatable_class_underscored}"
    end

    def redirect_session_key
      :"passwordless_prev_location--#{@@authenticatable_class}"
    end

    # Deprecated
    def cookie_name(authenticatable_class)
      :"#{authenticatable_class.base_class.to_s.underscore}_id"
    end
  end
end
