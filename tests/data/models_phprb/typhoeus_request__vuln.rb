# expect: DF010
class DemoController < ApplicationController
  def show
    Typhoeus::Request.new(params[:url]).run
  end
end
