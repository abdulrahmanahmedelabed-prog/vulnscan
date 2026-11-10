# expect: DF004
class DemoController < ApplicationController
  def show
    User.where.not("role = '#{params[:role]}'")
  end
end
