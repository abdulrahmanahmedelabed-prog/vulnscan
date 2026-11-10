# expect-none: DF012
class DemoController < ApplicationController
  def show
    type = params[:type]
    klass = type.constantize if %w[Invoice Receipt].include?(type)
  end
end
