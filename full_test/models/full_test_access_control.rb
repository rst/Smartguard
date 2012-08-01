module FullTestAccessControl

  OWNER_ATTRS_GROUP = ['owner', 'owner_id', 'owner_firm', 'owner_firm_id']

  def self.included( klass )
    klass.class_eval do 
      include Access::Controlled
      declare_access_control_keys 'id', 'owner_id', 'owner_firm_id'
      declare_attribute_block_set_groups OWNER_ATTRS_GROUP
    end
  end
  
end
