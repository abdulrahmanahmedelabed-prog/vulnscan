require 'sinatra'

class Greeter
  def hello(name)
    "hi #{name}"
  end
  alias_method :hi, :hello
  alias greet hello
  undef to_s
end

get '/run' do
  system("ls " + params[:dir])   # still analysed after the indented alias lines: DF002
end
