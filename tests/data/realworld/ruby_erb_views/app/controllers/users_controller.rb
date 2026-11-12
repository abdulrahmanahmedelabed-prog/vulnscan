class UsersController < ApplicationController
  def show
    @user = User.find(params[:id])
    @greeting = params[:greeting]
    @motd = "Welcome"
  end
end
