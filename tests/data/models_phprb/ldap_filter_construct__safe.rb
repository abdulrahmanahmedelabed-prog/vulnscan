# expect-none: DF014
class DemoController < ApplicationController
  def show
    f = Net::LDAP::Filter.construct("(mail=#{Net::LDAP::Filter.escape(params[:mail])})")
  end
end
