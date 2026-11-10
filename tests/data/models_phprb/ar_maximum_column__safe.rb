# expect-none: DF004
class DemoController < ApplicationController
  def show
    Order.maximum(:total)
  end
end
