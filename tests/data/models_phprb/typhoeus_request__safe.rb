# expect-none: DF010
class DemoController < ApplicationController
  def show
    Typhoeus::Request.new('https://api.example.com/x').run
  end
end
