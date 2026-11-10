# expect-none: DF004
class DemoController < ApplicationController
  def show
    Session.delete_by(token: params[:token])
  end
end
