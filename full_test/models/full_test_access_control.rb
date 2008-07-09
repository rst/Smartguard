module FullTestAccessControl

  def self.included( klass )
    klass.class_eval do 
      include Access::Controlled
      declare_access_control_keys 'id', 'owner_id', 'owner_firm_id'
      declare_attribute_block_set_groups ['owner', 'owner_id', 
                                          'owner_firm', 'owner_firm_id']
    end
  end
  
end
