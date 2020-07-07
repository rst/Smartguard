$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "smartguard/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "smartguard"
  s.version     = Smartguard::VERSION
  s.authors     = ["Robert Thau"]
  s.email       = ["rst@smartleaf.com"]
  s.homepage    = ""
  s.summary     = "The godzilla of Rails permissioning plugins."
  s.description = "The godzilla of Rails permissioning plugins."

  s.files = Dir["{app,config,db,lib}/**/*"] + ["MIT-LICENSE", "Rakefile", "README.rdoc"]
  s.test_files = Dir["test/**/*"]

  s.add_dependency "rails", ">= 5.2"

  s.add_development_dependency "sqlite3"
end
