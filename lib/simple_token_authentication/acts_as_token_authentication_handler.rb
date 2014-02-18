module SimpleTokenAuthentication
  module ActsAsTokenAuthenticationHandlerMethods
    extend ActiveSupport::Concern

    # Please see https://gist.github.com/josevalim/fb706b1e933ef01e4fb6
    # before editing this file, the discussion is very interesting.

    included do
      private :authenticate_account_from_token!
      # This is our new function that comes before Devise's one
      before_filter :authenticate_account_from_token!
      # This is Devise's authentication
      before_filter :authenticate_account!
    end

    # For this example, we are simply using token authentication
    # via parameters. However, anyone could use Rails's token
    # authentication features to get the token from a header.
    def authenticate_account_from_token!
      # Set the authentication token params if not already present,
      # see http://stackoverflow.com/questions/11017348/rails-api-authentication-by-headers-token
      if account_token = params[:account_token].blank? && request.headers["X-Account-Token"]
        params[:account_token] = account_token
      end
      if account_email = params[:account_email].blank? && request.headers["X-Account-Email"]
        params[:account_email] = account_email
      end

      account_email = params[:account_email].presence
      # See https://github.com/ryanb/cancan/blob/1.6.10/lib/cancan/controller_resource.rb#L108-L111
      if Account.respond_to? "find_by"
        account = account_email && Account.find_by(email: account_email)
      elsif Account.respond_to? "find_by_email"
        account = account_email && Account.find_by_email(account_email)
      end

      # Notice how we use Devise.secure_compare to compare the token
      # in the database with the token given in the params, mitigating
      # timing attacks.
      if account && Devise.secure_compare(account.authentication_token, params[:account_token])
        # Notice we are passing store false, so the account is not
        # actually stored in the session and a token is needed
        # for every request. If you want the token to work as a
        # sign in token, you can simply remove store: false.
        sign_in account, store: false
      end
    end
  end

  module ActsAsTokenAuthenticationHandler
    extend ActiveSupport::Concern

    # I have insulated the methods into an additional module to avoid before_filters
    # to be applied by the `included` block before acts_as_token_authentication_handler was called.
    # See https://github.com/gonzalo-bulnes/simple_token_authentication/issues/8#issuecomment-31707201

    included do
      # nop
    end

    module ClassMethods
      def acts_as_token_authentication_handler(options = {})
        include SimpleTokenAuthentication::ActsAsTokenAuthenticationHandlerMethods
      end
    end
  end
end
ActionController::Base.send :include, SimpleTokenAuthentication::ActsAsTokenAuthenticationHandler
