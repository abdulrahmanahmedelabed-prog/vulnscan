# expect: DF013
class DemoController < ApplicationController
  def show
    @bio = params[:bio].html_safe
  end
end
