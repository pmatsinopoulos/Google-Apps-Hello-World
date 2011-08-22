class HomeController < ApplicationController
  skip_before_filter :authenticate!, :only => [:manifest, :support]

  def index
  end

  # GET /manifest.xml
  #
  def manifest
    respond_to do |format|
      format.xml
      render :layout => false and return
    end
  end

  # GET /support
  #
  def support
  end

  # GET /setup
  def setup

    logger.debug "Setup is starting ..."

    callback = params[:callback]

    # get the admin user details and register him immediately

    # get the open id
    open_id = params[:open_id]

    # authenticate admin user
    headers['WWW-Authenticate'] = Rack::OpenID.build_header(
      :identifier => open_id,
      :required => ["http://axschema.org/contact/email"],
      :return_to => setup_authentication_complete_url(:only_path => false),
      :method => 'post'
    )
    logger.debug("headers: #{headers.inspect}")
    render :nothing => true, :status => "401"

  end

  # POST /setup_authentication_complete
  #
  # Thes is called when authentication of admin at setup step is complete
  def setup_authentication_complete
    logger.debug("setup authentication complete called")
    logger.debug("Request inspect: #{request.inspect}")
    logger.debug("Request params: #{params}")

    resp = request.env["rack.openid.response"]
    if resp.present?
      if resp.status == :success
        logger.debug("rack.openid.response is present and success: #{resp.inspect}")

        # we have the setup user successfully authenticated
        ax = OpenID::AX::FetchResponse.from_success_response(resp)
        email = ax.get_single("http://axschema.org/contact/email")
        logger.debug("...done: #{email}")

        # register user
        logger.debug("about to save user")
        u = User.new(:email => email, :open_id => params[:open_id], :admin_user => true )
        begin
          u.save!
          logger.debug("User saved successfully!")
        rescue Exception ex
          logger.error "Error saving user"
          logger.error ex.message
          logger.error ex.backtrace
        end

        # return to call back
        logger.debug "About to return to callback: #{params[:callback]}"
        redirect_to params[:callback]

      end
    end

  end

end
