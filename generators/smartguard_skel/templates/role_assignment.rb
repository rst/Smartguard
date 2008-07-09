class RoleAssignment < ActiveRecord::Base

  include Access::Controlled
  include SmartguardBasicRoleAssignment

end
