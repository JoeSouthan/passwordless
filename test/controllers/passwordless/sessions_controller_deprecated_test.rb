# frozen_string_literal: true

require "test_helper"

module Passwordless
  class SessionsControllerDeprecatedTest < ActionDispatch::IntegrationTest
    test "signing out removes cookies" do
      user = User.create email: "a@a"

      cookies[:user_id] = user.id
      assert_not_nil cookies[:user_id]

      get "/users/sign_out"
      follow_redirect!

      assert_equal 200, status
      assert_equal "/", path
      assert cookies[:user_id].blank?
    end
  end
end
