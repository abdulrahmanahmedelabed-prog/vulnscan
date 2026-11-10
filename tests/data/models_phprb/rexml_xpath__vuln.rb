# expect: DF015
class DemoController < ApplicationController
  def show
    REXML::XPath.first(doc, "//user[@id='#{params[:id]}']")
  end
end
