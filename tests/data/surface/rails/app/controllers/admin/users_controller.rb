module Admin
  class UsersController < ApplicationController
    before_action :require_admin

    def destroy
      User.find(params[:id]).destroy
    end

    def export
      send_file "/srv/exports/#{params[:name]}"
    end
  end
end
