class SmartguardSkelGenerator < Rails::Generator::Base

  def manifest
    record do |m|

      m.migration_template 'create_roles.rb', 'db/migrate',
        :migration_file_name => 'create_roles'
      m.migration_template 'create_role_assignments.rb', 'db/migrate',
        :migration_file_name => 'create_role_assignments'
      m.migration_template 'create_permissions.rb', 'db/migrate',
        :migration_file_name => 'create_permissions'

      m.directory 'app/models'
      m.template 'role.rb',            'app/models/role.rb'
      m.template 'role_assignment.rb', 'app/models/role_assignment.rb'
      m.template 'permission.rb',      'app/models/permission.rb'

      m.directory 'test/unit'
      m.template 'smartguard_test.rb', 'test/unit/smartguard_test.rb'

      m.readme 'README'

    end
  end

end
