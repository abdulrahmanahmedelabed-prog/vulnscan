# expect-none: DF015
class DemoController < ApplicationController
  def show
    REXML::XPath.first(doc, '//user[@id=$id]', nil, { 'id' => params[:id] })
  end
end
