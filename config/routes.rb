GappsMplace::Application.routes.draw do

  controller :sessions do
    get "/login", :action => "new"
    post "/login", :action => "create"
    post "/logout", :action => "destroy"
  end

  controller :home do
    get "index"
    get "manifest"
    get "support"
  end

  root :to => "home#index", :as => :home

end
