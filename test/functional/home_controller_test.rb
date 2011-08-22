require 'test_helper'

class HomeControllerTest < ActionController::TestCase

  test "routing" do

    assert_recognizes({:controller => "home", :action => "support"}, "/support")
    assert_generates("/support", {:controller => "home", :action => "support"})

  end

end
