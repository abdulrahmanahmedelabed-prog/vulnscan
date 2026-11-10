# expect-none: DF007
class DemoController < ApplicationController
  def show
    ERB.new(File.read('app/views/report.erb')).result_with_hash(name: params[:name])
  end
end
