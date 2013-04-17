$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "smartguard/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "smartguard"
  s.version     = Smartguard::VERSION
  s.authors     = ["Robert Thau and collaborators"]
  s.email       = ["rst@ai.mit.edu"]
  s.homepage    = "http://dev.smartleaf.com/smartguard"
  s.summary     = "A model-level, role-based access control package for Rails"
  s.description = <<-EOF
    Smartguard provides a flexible framework for declaring who can do
    what to ActiveRecord model objects.  It stores the permission
    structure in the database, allowing it to be manipulated at
    runtime, including creating new roles, assigning them to users,
    and changing the permissions associated with a role.  (Permissions
    grant a particular privilege on some or all objects of a given
    class, as determined by particular attributes designated as access
    control keys.)  It also allows programmers to easily declare what
    privileges are required to, say, save a model object, delete it,
    or set particularly sensitive attributes.
  EOF

  s.files = Dir["{app,config,db,lib}/**/*"] + ["MIT-LICENSE", "Rakefile", "README.rdoc"]
  s.test_files = Dir["test/**/*"]

  s.add_dependency "rails", "~> 3.2.12"

  s.add_development_dependency "sqlite3"
end
