# expect-none: DF010
class DemoController < ApplicationController
  def show
    conn = Faraday.new(url: 'https://api.example.com')
  end
end
