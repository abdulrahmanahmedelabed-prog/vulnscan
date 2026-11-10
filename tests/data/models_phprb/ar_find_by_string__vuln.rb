# expect: DF004
class DemoController < ApplicationController
  def show
    User.find_by("email = '#{params[:email]}'")
  end
end
