# expect: DF004
class DemoController < ApplicationController
  def show
    Order.maximum(params[:column])
  end
end
