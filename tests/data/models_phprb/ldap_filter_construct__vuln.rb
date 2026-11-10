# expect: DF014
class DemoController < ApplicationController
  def show
    f = Net::LDAP::Filter.construct("(mail=#{params[:mail]})")
  end
end
