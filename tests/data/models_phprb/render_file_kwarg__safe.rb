# expect-none: DF005
class DemoController < ApplicationController
  def show
    render file: Rails.root.join('public', '404.html')
  end
end
