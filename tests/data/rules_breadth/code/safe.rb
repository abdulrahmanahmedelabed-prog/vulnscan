require "jwt"
require "net/http"

def load(token, http, url, key)
  payload = JWT.decode(token, key, true, algorithm: "HS256")
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  RestClient::Request.execute(url: url, method: :get, verify_ssl: true)
  payload
end
