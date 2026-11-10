# expect: DF015
class DemoController < ApplicationController
  def show
    doc.xpath("//user[name='#{params[:name]}']")
  end
end
