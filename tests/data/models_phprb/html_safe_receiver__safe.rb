# expect-none: DF013
class DemoController < ApplicationController
  def show
    @bio = ERB::Util.h(params[:bio]).html_safe
  end
end
