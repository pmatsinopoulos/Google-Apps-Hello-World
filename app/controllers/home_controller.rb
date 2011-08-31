require 'gapps_openid'
require 'rack/openid'
require 'google_util'
require 'oauth_util'

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

    user = User.find(session[:user_id])

    callback_url = display_organization_name_url(:only_path => false)

    consumer_key = Settings.google_apps_market.consumer.key
    consumer_secret = Settings.google_apps_market.consumer.secret

    get_request_token_url = "https://www.google.com/accounts/OAuthGetRequestToken"
    scope = "https://apps-apis.google.com/a/feeds/domain/"

    oauth_util = OauthUtil.new

    parsed_url = URI.parse("#{get_request_token_url}?".concat([
        "oauth_callback=#{oauth_util.percent_encode(callback_url)}",
        "oauth_consumer_key=#{oauth_util.percent_encode(consumer_key)}",
        "oauth_signature_method=HMAC-SHA1",
        "scope=#{oauth_util.percent_encode(scope)}" ].join('&')))

    oauth_util.consumer_key = consumer_key
    oauth_util.consumer_secret = consumer_secret
    with_signature = oauth_util.sign(parsed_url).query_string
    logger.debug("With signature: #{with_signature}")

    http = Net::HTTP.new(parsed_url.host, parsed_url.port)
    http.use_ssl = true
    req = Net::HTTP::Get.new("#{parsed_url.path}?#{with_signature}")
    res = http.request(req)

    logger.debug("Response body: #{res.body}")
    logger.debug("Response inspect: #{res.inspect}")

    if res.is_a?(Net::HTTPSuccess)
      # let us get
      # 1) oauth_token
      # 2) oauth_token_secret
      # 3) oauth_callback_confirmed
      response_values = Hash.new
      res.body.split('&').each{ |e| response_values[ e.split('=')[0] ] = URI.unescape(e.split('=')[1]) }
      logger.debug("Oauth token = #{response_values['oauth_token']}")
      logger.debug("Oauth token secret = #{response_values['oauth_token_secret']}")
      logger.debug("Oauth callback confirmed = #{response_values['oauth_callback_confirmed']}")

      # do the OAuthAuthorizeToken
      authorize_token_url = "https://www.google.com/accounts/OAuthAuthorizeToken?oauth_token=#{URI.escape(response_values['oauth_token'])}"
      # save oauth_token_secret in session
      session[:oauth_token_secret] = response_values['oauth_token_secret']

      redirect_to authorize_token_url

    else
        res.error!
    end

  end

  def display_organization_name

    user = User.find(session[:user_id])

    oauth_token = params[:oauth_token]
    oauth_verifier = params[:oauth_verifier]
    oauth_token_secret = session[:oauth_token_secret]

    # will call the get access token
    consumer_key = Settings.google_apps_market.consumer.key
    consumer_secret = Settings.google_apps_market.consumer.secret

    get_access_token_url = "https://www.google.com/accounts/OAuthGetAccessToken"

    oauth_util = OauthUtil.new

    parsed_url = URI.parse("#{get_access_token_url}?".concat([
        "oauth_consumer_key=#{oauth_util.percent_encode(consumer_key)}",
        "oauth_token=#{oauth_util.percent_encode(oauth_token)}",
        "oauth_verifier=#{oauth_util.percent_encode(oauth_verifier)}",
        "oauth_signature_method=HMAC-SHA1"
         ].join('&')))

    oauth_util.consumer_key = consumer_key
    oauth_util.consumer_secret = consumer_secret
    oauth_util.token_secret = oauth_token_secret
    with_signature = oauth_util.sign(parsed_url).query_string
    logger.debug("With signature: #{with_signature}")

    http = Net::HTTP.new(parsed_url.host, parsed_url.port)
    http.use_ssl = true
    all_get_url = "#{parsed_url.path}?#{with_signature}"
    logger.debug("All get url: #{all_get_url}")
    req = Net::HTTP::Get.new(all_get_url)
    res = http.request(req)

    logger.debug("Response body: #{res.body}")
    logger.debug("Response inspect: #{res.inspect}")

    if res.is_a?(Net::HTTPSuccess)
      response_values = Hash.new
      res.body.split('&').each{ |e| response_values[ e.split('=')[0] ] = URI.unescape(e.split('=')[1]) }
      logger.debug("Oauth token = #{response_values['oauth_token']}")
      logger.debug("Oauth token secret = #{response_values['oauth_token_secret']}")

      get_domain_organization_name_url = "https://apps-apis.google.com/a/feeds/domain/2.0/fraudpointer.com/general/organizationName"
      oauth_util = OauthUtil.new
      parsed_url = URI.parse("#{get_domain_organization_name_url}?".concat([
        "oauth_signature_method=HMAC-SHA1",
        "oauth_token=#{oauth_util.percent_encode(response_values['oauth_token'])}" ].join('&')))
      oauth_util.consumer_key = consumer_key
      oauth_util.consumer_secret = consumer_secret
      oauth_util.token_secret = oauth_token_secret
      with_signature = oauth_util.sign(parsed_url).query_string
      logger.debug("With signature: #{with_signature}")

      http = Net::HTTP.new(parsed_url.host, parsed_url.port)
      http.use_ssl = true
      req = Net::HTTP::Get.new("#{parsed_url.path}?#{with_signature}")
      res = http.request(req)

      logger.debug("Response body: #{res.body}")
      logger.debug("Response inspect: #{res.inspect}")

      @events = []
      feed.elements.each('//entry') do |entry|
        @events << entry
      end

    else
      res.error!
    end

  end

  def user_info
    user = User.find(session[:user_id])

    email = user.email
    consumer_key = Settings.google_apps_market.consumer.key
    consumer_secret = Settings.google_apps_market.consumer.secret

    url = "https://apps-apis.google.com/a/feeds/customer/2.0/customerId?xoauth_requestor_id=#{URI.escape(email)}"
    parsed_url = URI.parse(url)

    consumer = OAuth::Consumer.new(consumer_key, consumer_secret)
    method = "get"
    oauth_params = {:consumer => consumer, :method => method, :request_uri => parsed_url.to_s}

    http = Net::HTTP.new(parsed_url.host, parsed_url.port)
    http.use_ssl = (parsed_url.port == 443)
    req = Net::HTTP::Get.new(parsed_url.request_uri)
    oauth_helper = OAuth::Client::Helper.new(req, oauth_params)
    req.initialize_http_header(headers.merge({'Authorization' => oauth_helper.header}))

    res = http.request(req)
    logger.debug("Response body: #{res.body}")
    logger.debug("Response: #{res}")

  end

end
