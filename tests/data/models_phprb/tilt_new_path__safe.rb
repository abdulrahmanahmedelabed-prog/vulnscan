# expect-none: DF005
class DemoController < ApplicationController
  def show
    Tilt.new('app/views/home.erb').render
  end
end
