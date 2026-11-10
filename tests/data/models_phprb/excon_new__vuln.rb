# expect: DF010
class DemoController < ApplicationController
  def show
    Excon.new(params[:url]).get
  end
end
