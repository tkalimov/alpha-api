module ApplicationHelper
	
	def cors_set_access_control_headers
          headers['Access-Control-Allow-Headers'] = 'user-token'
          headers['Access-Control-Allow-Origin'] = 'http://localhost:8000'
          headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
          headers['Access-Control-Allow-Credentials'] = 'true'
    end
end
