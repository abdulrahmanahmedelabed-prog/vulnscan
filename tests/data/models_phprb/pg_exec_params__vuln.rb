# expect: DF004
class DemoController < ApplicationController
  def show
    conn.exec_params("SELECT * FROM t WHERE a = '#{params[:a]}'", [])
  end
end
