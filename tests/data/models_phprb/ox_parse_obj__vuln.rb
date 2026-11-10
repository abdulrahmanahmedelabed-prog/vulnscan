# expect: DF006
class DemoController < ApplicationController
  def show
    obj = Ox.parse_obj(params[:xml])
  end
end
