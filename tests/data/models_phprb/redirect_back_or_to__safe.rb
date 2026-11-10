# expect-none: DF008
class DemoController < ApplicationController
  def show
    redirect_back_or_to root_path
  end
end
