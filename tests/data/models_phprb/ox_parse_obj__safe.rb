# expect-none: DF006
class DemoController < ApplicationController
  def show
    doc = Ox.parse(params[:xml])
  end
end
