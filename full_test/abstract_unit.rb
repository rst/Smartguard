#--
# Copyright (c) 2007 Robert S. Thau, Smartleaf, Inc.
# Copyright (c) 2005 Rick Olson
# 
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#++

# Based on test driver code from technoweenie's acts_as_versioned.
# Most of this is actually pretty generic...

$:.unshift(File.dirname(__FILE__) + '/../../../rails/activesupport/lib')
$:.unshift(File.dirname(__FILE__) + '/../../../rails/activerecord/lib')
$:.unshift(File.dirname(__FILE__) + '/../../../rails/actionpack/lib')
$:.unshift(File.dirname(__FILE__) + '/../lib')
$:.unshift(File.dirname(__FILE__) + '/models')

require 'test/unit'
begin
  require 'active_support'
  require 'active_record'
  require 'active_record/fixtures'
  require 'action_controller'
  require 'action_view'
rescue LoadError
  require 'rubygems'
  retry
end

require(File.dirname(__FILE__) + '/../init.rb')

config = YAML::load(IO.read(File.dirname(__FILE__) + '/database.yml'))
ActiveRecord::Base.colorize_logging = false
ActiveRecord::Base.logger = Logger.new(File.dirname(__FILE__) + "/debug.log")

selected_config = config[ENV['DB'] || 'sqlite']
ActiveRecord::Base.configurations = {'test' => selected_config}
ActiveRecord::Base.establish_connection( selected_config )

load(File.dirname(__FILE__) + "/schema.rb")

Test::Unit::TestCase.fixture_path = File.dirname(__FILE__) + "/fixtures/"
$:.unshift(Test::Unit::TestCase.fixture_path)

class Test::Unit::TestCase #:nodoc:

  self.use_transactional_fixtures = true
  self.use_instantiated_fixtures  = false

  def assert_valid( x )
    assert x.valid?, x.errors.full_messages.join("\n")
  end

  # Plugin-specific test helpers below here:

  def self.use_all_fixtures
    fixtures :firms, :role_assignments, :users, :roles, :permissions, :blogs
  end

  include Access::TestHelpers

  # Returns a Permission granting 'privilege' on any object of class 'klass'
  # whose owner_firm is set to 'firm'.

  def owner_firm_perm privilege, klass, firm
    Permission.new( :privilege    => privilege,
                    :class_name   => klass.name,
                    :is_grant     => false,
                    :has_grant_option => false,
                    :target_owned_by_self => false,
                    :target_owner_firm => firm
                    )
    
  end

end

require 'access_db_helpers'
require 'full_test_access_control'
