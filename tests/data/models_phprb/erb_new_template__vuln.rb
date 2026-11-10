# expect: DF007
class DemoController < ApplicationController
  def show
    ERB.new(params[:template]).result(binding)
  end
end
