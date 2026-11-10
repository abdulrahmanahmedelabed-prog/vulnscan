# expect-none: DF010
class DemoController < ApplicationController
  def show
    HTTPX.get('https://api.example.com/status')
  end
end
