Rails.application.routes.draw do
  root 'home#index'
  get '/search', to: 'products#search'
  resources :products, only: [:index, :show, :create] do
    member do
      post :publish
    end
  end
  namespace :admin do
    resources :users, only: [:destroy]
    get 'export', to: 'users#export'
  end
  mount Sidekiq::Web => '/sidekiq'
end
