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
    get "setup"
    post "setup_authentication_complete"
    get "calendar"
    get "organization_name"
    get "display_organization_name"
  end

  root :to => "home#index", :as => :home

end
