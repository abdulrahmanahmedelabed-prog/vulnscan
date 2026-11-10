# expect: DF002
class DemoController < ApplicationController
  def show
    q = request.query_parameters['q']
    system("grep #{q} /var/log/app.log")
  end
end
