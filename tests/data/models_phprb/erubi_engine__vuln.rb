# expect: DF007
class DemoController < ApplicationController
  def show
    src = Erubi::Engine.new(params[:tpl]).src
  end
end
