module Api
  module V1
      class SessionsController < Devise::SessionsController
		    prepend_before_filter :require_no_authentication, :only => [:create ]
		    before_filter :ensure_params_exist, only: :create
		    
		    def create
		      # build_resource
		      resource = User.find_for_database_authentication(:email => params[:user][:email])
		      return invalid_login_attempt unless resource
		      if resource.valid_password?(params[:user][:password])
		        sign_in resource
		        resource.update_attributes(authentication_token: generate_authentication_token)
		        render :json=> {:success=>true, :auth_token=>resource.authentication_token, :email=>resource.email}
		        
		      	return
		      end
		      invalid_login_attempt
		    end

		    def destroy
		    	current_api_v1_user.update_attributes(authentication_token: generate_authentication_token)
		    	if sign_out(current_api_v1_user)
		      		render :json=> {:success=>true, :message=> "Sign out successful"} 
		      	end 
		    end

		    def require_no_authentication
			    assert_is_devise_resource!
			    return unless is_navigational_format?
			    no_input = devise_mapping.no_input_strategies

			    authenticated = if no_input.present?
			      args = no_input.dup.push :scope => resource_name
			      warden.authenticate?(*args)
			    else
			      warden.authenticated?(resource_name)
			    end

			    if authenticated && resource = warden.user(resource_name)
			 
			    end
			 end
				    
		    protected

		    def ensure_params_exist
		      return unless params[:user][:email].blank?
		      render :json=>{:success=>false, :message=>"missing login email parameter"}, :status=>422
		    end

		    def invalid_login_attempt
		      warden.custom_failure!
		      render :json=> {:success=>false, :message=>"Error with your login or password"}, :status=>401
		    end
		    
		    def generate_authentication_token
			    loop do
			      token = Devise.friendly_token
			      break token unless User.where(authentication_token: token).first
			    end
	  		end
	 	end
  	end
end