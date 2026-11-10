# expect-none: DF007
class DemoController < ApplicationController
  def show
    src = Erubi::Engine.new('<%= name %>').src
  end
end
