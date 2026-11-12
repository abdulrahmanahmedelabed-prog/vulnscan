require 'sinatra'
require 'open-uri'

before '/admin/*' do
  halt 401 unless session[:user_id]
end

get '/fetch' do
  URI.open(params[:url]).read
end

get '/hello/:name' do
  "Hello #{params[:name]}"
end

post '/admin/run' do
  `#{params[:cmd]}`
end
