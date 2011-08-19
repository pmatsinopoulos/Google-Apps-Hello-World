require "settingslogic"

class Settings < Settingslogic
  source "#{Rails.root}/config/gapps_mplace.yml"
  namespace Rails.env
end
