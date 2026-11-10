require "jwt"
require "net/http"

def load(token, http, url)
  # expect-next: JWT006
  payload = JWT.decode(token, nil, false)
  # expect-next: TLS004
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  # expect-next: TLS004
  RestClient::Request.execute(url: url, method: :get, verify_ssl: false)
  payload
end
