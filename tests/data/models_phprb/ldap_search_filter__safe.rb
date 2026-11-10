# expect-none: DF014
class DemoController < ApplicationController
  def show
    ldap.search(base: 'dc=example,dc=com', filter: Net::LDAP::Filter.equals('uid', params[:uid]))
  end
end
