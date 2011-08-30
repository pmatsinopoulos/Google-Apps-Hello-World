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

    consumer_key = Settings.google_apps_market.consumer.key
    consumer_secret = Settings.google_apps_market.consumer.secret

    #oauth_consumer = OAuth::Consumer.new(Settings.google_apps_market.consumer.key, Settings.google_apps_market.consumer.secret)
    #
    #request_token = oauth_consumer.get_request_token(:oauth_callback => callback_url)
    #session[:request_token] = request_token
    #redirect_to request_token.authorize_url(:oauth_callback => callback_url)

    nonce = generate_nonce
    get_request_token_url = "https://www.google.com/accounts/OAuthGetRequestToken"
    scope = "https://apps-apis.google.com/a/feeds/domain/"
    oauth_timestamp = Time.now.to_i
    logger.debug("Timestamp: #{oauth_timestamp}")
    base_string = ["GET", escape(get_request_token_url),
                    ["oauth_callback%3D#{escape(callback_url)}",
                     "oauth_consumer_key%3D#{URI.escape(consumer_key)}",
                     "oauth_nonce%3D#{nonce}",
                     "oauth_signature_method%3DHMAC-SHA1",
                     "oauth_timestamp%3D#{oauth_timestamp}",
                     "scope%3D#{escape(scope)}"].join('%26') ].join('&')
    oauth_signature = generate_signature(escape(consumer_secret), base_string)
    logger.debug("Nonce: #{nonce}")
    logger.debug("Signature: #{oauth_signature}")
    url = URI.parse("#{get_request_token_url}?".concat([
        "oauth_callback=#{escape(callback_url)}",
        "oauth_consumer_key=#{consumer_key}",
        "oauth_nonce=#{nonce}",
        "oauth_signature_method=HMAC-SHA1",
        "oauth_signature=#{URI.escape(oauth_signature)}",
        "oauth_timestamp=#{oauth_timestamp}",
        "scope=#{escape(scope)}" ].join('&')))
    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = true
    req = Net::HTTP::Get.new(url.request_uri)
    res = http.request(req)
    logger.debug("Response body: #{res.body}")

  end

  def escape(value)
    URI.escape(value, Regexp.new("[^#{URI::PATTERN::UNRESERVED}]"))
  end

  def generate_nonce
    rand(10 ** 30).to_s.rjust(30,'0')
  end

  def generate_signature(key, base_string)
    digest = OpenSSL::Digest::Digest.new('sha1')
    hmac = OpenSSL::HMAC.digest(digest, key, base_string )
    Base64.encode64(hmac).chomp.gsub(/\n/, '')
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
