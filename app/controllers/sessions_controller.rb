require 'gapps_openid'
require 'rack/openid'

class SessionsController < ApplicationController
  skip_before_filter :authenticate!, :only => [:create, :new, :destroy]

  # GET "/login"
  #
  # This might be coming from Google Apps too, not only from redirection from a human that hits our app directly.
  # In case it comes from Google Apps, then it will be:
  #
  # GET "/login?openid_identifier=${DOMAIN_NAME}
  #
  def new
    open_id = params[:open_id]
    logger.debug("Open ID is #{open_id}")
    if open_id.present?
      logger.debug("is present")
      headers['WWW-Authenticate'] = Rack::OpenID.build_header(
          :identifier => open_id,
          :required => ["http://axschema.org/contact/email",
                        "http://axschema.org/namePerson/first",
                        "http://axschema.org/namePerson/last"],
          :return_to => login_url,
          :method => :post
      )
      render :nothing => true, :status => :unauthorized and return
    end
  end

  # POST "/login"
  #
  # This either comes from a posting of the login form, or from Google Apps sending a replying to
  # an authentication request
  #
  def create
    logger.debug("create called")
    logger.debug(request.inspect)

    resp = request.env["rack.openid.response"]
    if resp.present?

      # call from Google Apps
      if resp.status == :success
        logger.debug("rack.openid.response is present and success: #{resp.inspect}")

        # will need to get the e-mail
        logger.debug("about to request the email of the user")
        ax = OpenID::AX::FetchResponse.from_success_response(resp)
        email = ax.get_single("http://axschema.org/contact/email")
        logger.debug("...done: #{email}")

        # authenticate by e-mail
        authenticate_by_email? ? redirect_to(home_path) : render(:text => "Unauthorized", :status => :unauthorized)

      else

        render :text => "Error: #{resp.status}"

      end

    else

      # call from the login form
      # email should have been given on login form
      email = params[:open_id]
      authenticated_by_email? ? redirect_to(home_path) : render(:text => "Unauthorized", :status => :unauthorized)

    end

  end

  # POST "/logout
  #
  def destroy
    session[:user_id] = nil
    redirect_to login_path
  end

  private

  def authenticate_by_email?
    user_found = User.find_by_email(email) if email.present?
    if user_found.present?
      session[:user_id] = user_found.id
      return true
    end
    return false
  end

end