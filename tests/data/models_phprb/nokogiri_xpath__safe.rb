# expect-none: DF015
class DemoController < ApplicationController
  def show
    doc.xpath('//user[name=$name]', nil, name: params[:name])
  end
end
