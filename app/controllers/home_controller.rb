require 'gapps_openid'
require 'rack/openid'
require 'google_util'
require 'net/http'
require 'uri'

class HomeController < ApplicationController
  skip_before_filter :authenticate!, :only => [:manifest, :support, :setup, :setup_authentication_complete]

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

    logger.debug("Setup up start...callback is #{callback}")

    # get the admin user details and register him immediately

    # get the open id
    open_id = params[:open_id]

    # authenticate admin user
    headers['WWW-Authenticate'] = Rack::OpenID.build_header(
      :identifier => open_id,
      :required => ["http://axschema.org/contact/email"],
      :return_to => setup_authentication_complete_url(:only_path => false, :callback => callback, :open_id => open_id),
      :method => 'post'
    )
    logger.debug("headers: #{headers.inspect}")
    render :nothing => true, :status => "401"

  end

  # POST /setup_authentication_complete
  #
  # This is called when authentication of admin at setup step is complete
  def setup_authentication_complete
    logger.debug("setup authentication complete called")
    logger.debug("Request params: #{params.inspect}")

    callback = params[:callback]
    logger.debug("Callback is #{callback}")

    resp = request.env["rack.openid.response"]

    if resp.present?
      if resp.status == :success

        logger.debug("Response from authentication is success")

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
        rescue Exception => ex
          logger.error "Error saving user"
          logger.error ex.message
        end

        # return to call back
        logger.debug "About to return to callback: #{params[:callback]}"
        redirect_to callback

      end
    end

  end

  # GET /calendar
  def calendar
    # The call to /calendar has been authenticated. Hence, we have at session the user_id.
    user = User.find(session[:user_id])
    oauth_consumer = OAuth::Consumer.new(Settings.google_apps_market.consumer.key, Settings.google_apps_market.consumer.secret)
    access_token = OAuth::AccessToken.new(oauth_consumer)
    client = Google::Client.new(access_token, '2.0');
    feed = client.get('https://www.google.com/calendar/feeds/default/private/full', {
        'xoauth_requestor_id' => user.email,
        'orderby' => 'starttime',
        'singleevents' => 'true',
        'sortorder' => 'a',
        'start-min' => Time.now.strftime('%Y-%m-%dT%H:%M:%S')
    })
    render :text => "Unable to query calendar feed", :status => "500" and return if feed.nil?

    @events = []
    feed.elements.each('//entry') do |entry|
      @events << {
        :title => entry.elements["title"].text,
        :content => entry.elements["content"].text,
        :start_time => entry.elements["gd:when"].attribute("startTime").value,
        :end_time => entry.elements["gd:when"].attribute("endTime").value
      }
    end

  end

  def organization_name

    # The call to /calendar has been authenticated. Hence, we have at session the user_id.
    user = User.find(session[:user_id])

    callback_url = display_organization_name_url(:only_path => false)

    #oauth_consumer = OAuth::Consumer.new(Settings.google_apps_market.consumer.key, Settings.google_apps_market.consumer.secret)
    #
    #request_token = oauth_consumer.get_request_token(:oauth_callback => callback_url)
    #session[:request_token] = request_token
    #redirect_to request_token.authorize_url(:oauth_callback => callback_url)
    url = URI.parse("https://www.google.com/accounts/OAuthGetRequestToken")
    req = Net::HTTP::Get.new(url.path)
    res = Net::HTTP.start(url.host, url.port) {|http|
      http.request(req)
    }
    logger.debug("Response body: #{res.body}")

  end

  def display_organization_name
    request_token = session[:request_token]
    access_token = request_token.get_access_token

    client = Google::Client.new(access_token, '2.0')
    feed = client.get('https://apps-apis.google.com/a/feeds/domain/2.0/fraudpointer.com/general/organizationName', {
        'xoauth_requestor_id' => user.email
    })
    render :text => "Unable to query organization feed", :status => "500" and return if feed.nil?

    @events = []
    feed.elements.each('//entry') do |entry|
      @events << entry
    end
  end

end
