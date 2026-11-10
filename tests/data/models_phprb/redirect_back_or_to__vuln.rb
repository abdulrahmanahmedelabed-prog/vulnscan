# expect: DF008
class DemoController < ApplicationController
  def show
    redirect_back_or_to params[:return_to]
  end
end
