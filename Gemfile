source "http://rubygems.org"

# Declare your gem's dependencies in smartguard.gemspec.
# Bundler will treat runtime dependencies like base dependencies, and
# development dependencies will be added by default to the :development group.
gemspec

# jquery-rails is used by the dummy application
gem "jquery-rails"

# Other stuff used by the dummy

gem 'rails', '4.0.1'

gem 'ruby-oci8', '~> 2.1.0'
gem 'activerecord-oracle_enhanced-adapter', 
    git: '/home/rst/src/oracle-enhanced',
    branch: 'slmod_rails4'

# Declare any dependencies that are still in development here instead of in
# your gemspec. These might include edge Rails or gems from your path or
# Git. Remember to move these dependencies to your gemspec before releasing
# your gem to rubygems.org.

# To use debugger, and other tools...
gem 'debugger'
gem 'pry-rails'

# Kludge.  Should not be required, but need this for the two-arg
# 'attributes=' that was deleted along with the rest of protected-attrs...

gem 'protected_attributes'
