# expect-none: DF002
class DemoController < ApplicationController
  def show
    Open3.pipeline_r("ls #{Shellwords.escape(params[:dir])}") { |out, _ts| out.read }
  end
end
