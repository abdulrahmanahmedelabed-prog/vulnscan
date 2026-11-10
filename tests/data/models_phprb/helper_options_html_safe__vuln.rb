# expect: DF013
class SettingsController < ApplicationController
  def show
    @label = params[:label].html_safe
  end
end
