# expect: DF005
class DemoController < ApplicationController
  def show
    Tilt.new(params[:template]).render
  end
end
