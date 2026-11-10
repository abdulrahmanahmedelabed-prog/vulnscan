# expect: DF010
class DemoController < ApplicationController
  def show
    HTTPX.get(params[:url])
  end
end
