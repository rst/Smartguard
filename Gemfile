source "http://rubygems.org"

# Declare your gem's dependencies in smartguard.gemspec.
# Bundler will treat runtime dependencies like base dependencies, and
# development dependencies will be added by default to the :development group.
gemspec

# jquery-rails is used by the dummy application
gem "jquery-rails"

# Other stuff used by the dummy.  Drag in both pg and Oracle DB glue code...

gem 'rails', '~> 6.1.0'

gem 'pg', '>= 0.18', '< 2.0'

if ENV['ORACLE_HOME']
  #gem 'ruby-oci8', '~> 2.2.0'
  #gem 'activerecord-oracle_enhanced-adapter', '~> 5.2.0'
else
  # No ORACLE_HOME; presumably no Oracle header files present either,
  # and we'd need those to build the adapter's binary extensions.

  puts "ORACLE_HOME not set; skipping Oracle gems"
end

# Declare any dependencies that are still in development here instead of in
# your gemspec. These might include edge Rails or gems from your path or
# Git. Remember to move these dependencies to your gemspec before releasing
# your gem to rubygems.org.

# To use debugger, and other tools...
# gem 'debugger'
gem 'pry-rails'
gem 'pry-byebug'
