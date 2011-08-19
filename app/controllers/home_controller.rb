class HomeController < ApplicationController
  skip_before_filter :authenticate!, :only => [:manifest, :support]

  def index
  end

  # GET /manifest.xml
  #
  def manifest
    respond_to do |format|
      format.xml
      render :layout => false and return
    end
  end

  # GET /support
  #
  def support
  end

end
