require 'oauth'
require 'rexml/document'

# Simple helper around the ruby oauth library for making Google Data API requests
module Google
  class Client
    attr_accessor :oauth_token
    attr_accessor :version

    def initialize(token, version = '1.0')
      @token = token
      @version = version
    end

    def get(base, query_parameters)
      make_request(:get, url(base, query_parameters))
    end

    def make_request(method, url)
      response = @token.request(method, url, { 'GData-Version' => version })
      if response.is_a?(Net::HTTPFound)
        url = response['Location']
        return make_request(method, response['Location'])
      end
      return unless response.is_a?(Net::HTTPSuccess)
      REXML::Document.new(response.body)
    end

    private

    def url(base, query_parameters={})
      url = base
      unless query_parameters.empty?
        url += '?'
        query_parameters.each { |key, value|
          url += "#{CGI::escape(key)}=#{CGI::escape(value)}&"
        }
        url.chop!
      end
      url
    end
  end
end

