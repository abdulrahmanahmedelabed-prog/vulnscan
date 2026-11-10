# expect: DF012
class DemoController < ApplicationController
  def show
    klass = params[:type].constantize
    klass.new
  end
end
