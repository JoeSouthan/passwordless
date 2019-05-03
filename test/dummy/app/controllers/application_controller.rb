# frozen_string_literal: true

class ApplicationController < ActionController::Base
  include Passwordless::ControllerHelpers

  passwordless_for User

  protect_from_forgery with: :exception

  private

  def authenticate_user!
    return if current_user

    save_passwordless_redirect_location!(User)

    redirect_to root_path, flash: {error: "Not worthy!"}
  end
end
