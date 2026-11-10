# expect: DF014
class DemoController < ApplicationController
  def show
    ldap.search(base: 'dc=example,dc=com', filter: "(uid=#{params[:uid]})")
  end
end
