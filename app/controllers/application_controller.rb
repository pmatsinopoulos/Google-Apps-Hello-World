class ApplicationController < ActionController::Base

  class AuthenticationError < Exception; end

  protect_from_forgery

  before_filter :authenticate!

  helper_method :current_user

  # returns an authenticated user
  def current_user
    # gets id from session and retrieves the User from DB
    User.find(session[:user_id]) if session[:user_id].present?
  end

  # Checks if a user is logged or tries to authenticate from any possible combination (session, email + key, email + password).
  # If login fails returns +nil+. If authentication is successful returns the +User+ object.
  def authenticate!
    raise AuthenticationError unless authenticate
  end

  def authenticate
    authenticate_from_session || authenticate_from_google
  end

  # Tries to authenticate +User+ from session. If login fails returns +nil+.
  # If authentication is successful returns the +User+ object.
  def authenticate_from_session
    self.current_user
  end

  def authenticate_from_google
    # temporarily
    authenticate_from_session
  end

  # Handle Authentication errors
  rescue_from AuthenticationError do |exception|
    redirect_to login_path(:return_to => request.fullpath), :notice => "Please log in"
  end

end
