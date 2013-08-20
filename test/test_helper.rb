# Configure Rails Environment
ENV["RAILS_ENV"] = "test"

require File.expand_path("../dummy/config/environment.rb",  __FILE__)
require "rails/test_help"

Rails.backtrace_cleaner.remove_silencers!

# Load support files
Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].each { |f| require f }

# Load fixtures from the engine
ActiveSupport::TestCase.fixture_path = File.expand_path("../fixtures", __FILE__)

# Add some stock test helpers of our own.
require 'access_db_helpers'

class ActiveSupport::TestCase

  def assert_valid( x )
    assert x.valid?, x.errors.full_messages.join("\n")
  end

  # Plugin-specific test helpers below here:

  def self.use_all_fixtures
    fixtures :firms, :role_assignments, :users, :roles, :permissions, :blogs,
             :reports
  end

  include Access::TestHelpers

  # Returns a Permission granting 'privilege' on any object of class 'klass'
  # whose owner_firm is set to 'firm'.

  def owner_firm_perm( privilege, klass, firm )
    Permission.new( :privilege    => privilege,
                    :class_name   => klass.name,
                    :is_grant     => false,
                    :has_grant_option => false,
                    :target_owned_by_self => false,
                    :target_owner_firm => firm
                    )
    
  end

  # Returns a Permission granting 'privilege' on all objects of class 'klass'

  def wildcard_perm( privilege, klass )
    owner_firm_perm( privilege, klass, nil )
  end

end
