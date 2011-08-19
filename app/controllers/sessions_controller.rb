class SessionsController < ApplicationController
  skip_before_filter :authenticate!, :only => [:create, :new, :destroy]

  # GET "/login"
  #
  def new
  end

  # POST "/login"
  #
  def create
    session[:user_id] = User.first.id # temporarily I return the first user. Normally, it will try to authenticate user from Google.
    redirect_to home_path
  end

  # POST "/logout
  #
  def destroy
    session[:user_id] = nil
    redirect_to login_path
  end

end