# expect-none: DF004
class DemoController < ApplicationController
  def show
    conn.exec_params('SELECT * FROM t WHERE a = $1', [params[:a]])
  end
end
