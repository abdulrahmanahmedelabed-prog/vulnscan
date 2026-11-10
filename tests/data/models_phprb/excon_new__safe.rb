# expect-none: DF010
class DemoController < ApplicationController
  def show
    Excon.new('https://api.example.com').get
  end
end
