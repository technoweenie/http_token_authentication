# Makes it dead easy to do HTTP Token authentication.
#
# Simple Token example:
#
#   class PostsController < ApplicationController
#     TOKEN = "secret"
#
#     before_filter :authenticate, :except => [ :index ]
#
#     def index
#       render :text => "Everyone can see me!"
#     end
#
#     def edit
#       render :text => "I'm only accessible if you know the password"
#     end
#
#     private
#       def authenticate
#         authenticate_or_request_with_http_token do |token, options|
#           token == TOKEN
#         end
#       end
#   end
#
#
# Here is a more advanced Token example where only Atom feeds and the XML API is protected by HTTP token authentication,
# the regular HTML interface is protected by a session approach:
#
#   class ApplicationController < ActionController::Base
#     before_filter :set_account, :authenticate
#
#     protected
#       def set_account
#         @account = Account.find_by_url_name(request.subdomains.first)
#       end
#
#       def authenticate
#         case request.format
#         when Mime::XML, Mime::ATOM
#           if user = authenticate_with_http_token { |t, o| @account.users.authenticate(t, o) }
#             @current_user = user
#           else
#             request_http_token_authentication
#           end
#         else
#           if session_authenticated?
#             @current_user = @account.users.find(session[:authenticated][:user_id])
#           else
#             redirect_to(login_url) and return false
#           end
#         end
#       end
#   end
#
#
# In your integration tests, you can do something like this:
#
#   def test_access_granted_from_xml
#     get(
#       "/notes/1.xml", nil,
#       :authorization => ActionController::HttpAuthentication::Token.encode_credentials(users(:dhh).token)
#     )
#
#     assert_equal 200, status
#   end
#
#
# On shared hosts, Apache sometimes doesn't pass authentication headers to
# FCGI instances. If your environment matches this description and you cannot
# authenticate, try this rule in your Apache setup:
#
#   RewriteRule ^(.*)$ dispatch.fcgi [E=X-HTTP_AUTHORIZATION:%{HTTP:Authorization},QSA,L]
module HttpTokenAuthentication
  VERSION = '0.1.0'

  extend self

  module ControllerMethods
    def authenticate_or_request_with_http_token(realm = "Application", &login_procedure)
      authenticate_with_http_token(&login_procedure) || request_http_token_authentication(realm)
    end

    def authenticate_with_http_token(&login_procedure)
      HttpTokenAuthentication.authenticate(self, &login_procedure)
    end

    def request_http_token_authentication(realm = "Application")
      HttpTokenAuthentication.authentication_request(self, realm)
    end
  end

  # If token Authorization header is present, call the login procedure with 
  # the present token and options.
  #
  # controller      - ActionController::Base instance for the current request.
  # login_procedure - Proc to call if a token is present.  The Proc should 
  #                   take 2 arguments:
  #                     authenticate(controller) { |token, options| ... }
  #
  # Returns the return value of `&login_procedure` if a token is found.
  # Returns nil if no token is found.
  def authenticate(controller, &login_procedure)
    token, options = token_and_options(controller.request)
    if !token.blank?
      login_procedure.call(token, options)
    end
  end

  # Parses the token and options out of the token authorization header.  If
  # the header looks like this:
  #   Authorization: Token token="abc", nonce="def"
  # Then the returned token is "abc", and the options is {:nonce => "def"}
  #
  # request - ActionController::Request instance with the current headers.
  #
  # Returns an Array of [String, Hash] if a token is present.
  # Returns nil if no token is found.
  def token_and_options(request)
    if header = ActionController::HttpAuthentication::Basic.authorization(request).to_s[/^Token (.*)/]
      values = $1.split(',').
        inject({}) do |memo, value|
          value.strip!                      # remove any spaces between commas and values
          key, value = value.split(/\=\"?/) # split key=value pairs
          value.chomp!('"')                 # chomp trailing " in value
          value.gsub!(/\\\"/, '"')          # unescape remaining quotes
          memo.update(key => value)
        end
      [values.delete("token"), values.with_indifferent_access]
    end
  end

  # Encodes the given token and options into an Authorization header value.
  #
  # token   - String token.
  # options - optional Hash of the options.
  #
  # Returns String.
  def encode_credentials(token, options = {})
    values = ["token=#{token.to_s.inspect}"]
    options.each do |key, value|
      values << "#{key}=#{value.to_s.inspect}"
    end
    "Token #{values * ", "}"
  end

  # Sets a WWW-Authenticate to let the client know a token is desired.
  #
  # controller - ActionController::Base instance for the outgoing response.
  # realm      - String realm to use in the header.
  #
  # Returns nothing.
  def authentication_request(controller, realm)
    controller.headers["WWW-Authenticate"] = %(Token realm="#{realm.gsub(/"/, "")}")
    controller.__send__ :render, :text => "HTTP Token: Access denied.\n", :status => :unauthorized
  end
end
