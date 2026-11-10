# expect-none: DF010
class DemoController < ApplicationController
  def show
    http = Net::HTTP.new('api.example.com', 443)
  end
end
