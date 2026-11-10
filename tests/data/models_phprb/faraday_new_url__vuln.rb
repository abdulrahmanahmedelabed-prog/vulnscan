# expect: DF010
class DemoController < ApplicationController
  def show
    conn = Faraday.new(url: params[:endpoint])
  end
end
