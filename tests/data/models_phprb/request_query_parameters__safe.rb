# expect-none: DF002
class DemoController < ApplicationController
  def show
    q = request.query_parameters['q']
    system("grep #{Shellwords.escape(q)} /var/log/app.log")
  end
end
