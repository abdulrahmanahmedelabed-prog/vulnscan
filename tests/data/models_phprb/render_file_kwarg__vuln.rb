# expect: DF005
class DemoController < ApplicationController
  def show
    render file: "/srv/pages/#{params[:page]}"
  end
end
