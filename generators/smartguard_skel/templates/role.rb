class Role < ActiveRecord::Base

  include SmartguardBasicRole

  validates_length_of     :name, :within => 3..100

end
