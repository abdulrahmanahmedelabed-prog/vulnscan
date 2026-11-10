# expect: DF010
class DemoController < ApplicationController
  def show
    http = Net::HTTP.new(params[:host], 443)
  end
end
