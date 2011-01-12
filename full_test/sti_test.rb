#--
# Copyright (c) 2009 Robert S. Thau, Smartleaf, Inc.
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
require File.dirname(__FILE__) + '/abstract_unit'

# Don't have the ActiveSupport load_const magic, so we have to load
# the derived classes directly.  And we need to load their base class
# first, or it won't be defined when we load the derived classes.
# And *then* we need to put guards up around stuff in the base class,
# to deal with reloading when the fixtures code loads it explicitly.
# Sigh... 

require 'report'
require 'billing_report'
require 'activity_report'

require 'line_item'
require 'billing_line_item'

class StiTest < ActiveSupport::TestCase

  use_all_fixtures

  def setup
    with_permission( wildcard_perm( :find, Report )) do
      @all_reports     = Report.find :all
      @mertz_billing   = reports(:mertz_billing_report)
      @mertz_activity  = reports(:mertz_activity_report)
      @ricardo_billing = reports(:ricardo_billing_report)
    end
  end

  # Tests here don't try to duplicate everything we test for the
  # simple case, but do try to verify that everything was correctly
  # inherited...

  def test_loaded_everything
    assert @all_reports.detect{ |r| r.is_a?( ActivityReport ) }
    assert @all_reports.detect{ |r| r.is_a?( BillingReport ) }
    @all_reports.each do |rpt|
      assert_equal rpt.type, rpt.class.name
    end
  end

  def test_inheritance_basics
    [ :sg_access_control_keys, :sg_owner_access_control_key,
      :declared_privileges, :attribute_block_set_groups,
      :sg_reflected_privileges, :sg_deferred_permission_wrappers ].each do |k|
     assert_equal Report.send( k ), ActivityReport.send( k )
    end
  end

  def test_low_level
    p = owner_firm_perm( :rename, Report, firms(:mertz) )
    with_permission( p ) do
      assert  p.allows?( @mertz_billing,   :rename, User.current )
      assert !p.allows?( @ricardo_billing, :rename, User.current )
      assert  User.current.can?( :rename, @mertz_billing )
      assert !User.current.can?( :rename, @ricardo_billing )
      assert  @mertz_billing.permits?( :rename )
      assert !@ricardo_billing.permits?( :rename )
    end
  end

  def test_lifecycle_permissions

    assert_requires( owner_firm_perm( :find, Report, firms(:mertz) )) do
      Report.find @mertz_billing.id
    end

    assert_requires( owner_firm_perm( :find, Report, firms(:mertz) )) do
      BillingReport.find @mertz_billing.id
    end

    assert_requires( owner_firm_perm( :create, Report, firms(:mertz) )) do
      BillingReport.create! :name => 'another billing report',
        :owner => users(:fred), :owner_firm => firms(:mertz)
    end

    assert_requires( owner_firm_perm( :update_guarded, Report, firms(:mertz)),
                     owner_firm_perm( :update, Report, firms(:mertz)) 
                     ) do
      @mertz_billing.update_attributes! :guarded_int => 3

      # Grumpf.  Bug(?) in assert_requires; tries success option before
      # failures, with the result that some things that *should* fail
      # don't try to change guarded_int, and so succeed.  So set it back.

      @mertz_billing.guarded_int = nil
    end

    assert_requires( owner_firm_perm( :destroy, Report, firms(:mertz) )) do
      @mertz_billing.destroy
    end

  end

  def test_method_permissions

    assert_requires( wildcard_perm( :invoke_derived_method, Report )) do
      @mertz_billing.derived_method
    end

    assert_requires( wildcard_perm( :invoke_base_method, Report )) do
      @mertz_billing.base_method
    end

  end

  def test_attr_permissions
    assert_requires( wildcard_perm( :rename, Report )) do
      @mertz_billing.name = "Fred's billing report"
    end
  end

  def test_finds_and_counts
    with_permission( owner_firm_perm( :find, Report, firms(:mertz) )) do
      assert_find_match( Report.all_permitting(:find), "all" ) { |r|
        r.owner_firm == firms(:mertz)
      }
      assert_find_match( BillingReport.all_permitting(:find), "billing" ) { |r|
        r.is_a?( BillingReport ) && r.owner_firm == firms(:mertz)
      }
      assert_count_match( Report.count_permitting(:find), "all" ) { |r|
        r.owner_firm == firms(:mertz)
      }
      assert_count_match( BillingReport.count_permitting(:find), "billing"){|r|
        r.is_a?( BillingReport ) && r.owner_firm == firms(:mertz)
      }
    end
  end

  def assert_find_match( arr, msg = nil )
    wanted = @all_reports.select { |rpt| yield( rpt ) }
    assert_equal wanted.collect( &:id ).sort, arr.collect( &:id ).sort, msg
  end

  def assert_count_match( num, msg = nil )
    wanted = @all_reports.inject( 0 ) { |count, rpt| 
      yield( rpt )? count + 1 : count }
    assert_equal wanted, num, msg
  end

  # :to_associate permissions track mud in a wide variety of places.
  # These next tests try to hit all of them.

  def test_sti_belongs_to_set_on_associations

    item = BillingLineItem.new

    assert_requires( wildcard_perm( :add_line_item, Report ) ) do
      item.report = @ricardo_billing
    end

    assert_requires( wildcard_perm( :add_base_line_item, Report ) ) do
      item.billing_report = @ricardo_billing
    end

  end

  def test_sti_fk_set_on_associations

    item = BillingLineItem.new

    assert_requires( wildcard_perm( :add_line_item, Report )) do
      item.report_id = @ricardo_billing.id
    end

    assert_requires( wildcard_perm( :add_line_item, Report )) do
      item.report_id = nil
    end

    assert_requires( wildcard_perm( :add_base_line_item, Report )) do
      item.derived_report_id = @ricardo_billing.id
    end

    assert_requires( wildcard_perm( :add_base_line_item, Report )) do
      item.derived_report_id = nil
    end

  end

  def test_permits_create

    User.as( users(:unprivileged_guy) ) do
      assert !LineItem.permits_create?
    end

    User.as( users(:unprivileged_guy) ) do
      assert !BillingLineItem.permits_create?
    end

    with_permission( wildcard_perm( :add_line_item, Report) ) do
      assert BillingLineItem.permits_create?
    end

  end

  def test_permits_action

    it = nil

    with_permission( wildcard_perm( :add_line_item, Report )) do
      it = BillingLineItem.create! :report => @mertz_billing
    end

    assert_requires( wildcard_perm( :update, Report )) do
      raise PermissionFailure.new( 'x' ) unless it.permits_action?( :update )
    end

    assert_requires( wildcard_perm( :add_line_item, Report )) do
      raise PermissionFailure.new( 'x' ) unless it.permits_action?( :destroy )
    end

  end

  def test_permitted_associates

    it = BillingLineItem.new

    with_permission([owner_firm_perm(:add_line_item, Report, firms(:mertz)),
                     owner_firm_perm(:find,          Report, firms(:mertz))])do

      assocs = it.permitted_associates( :report )

      assert_equal 2, assocs.size
      assert assocs.include?( @mertz_billing )
      assert assocs.include?( @mertz_activity )

    end

  end

  def test_users_permitted
    with_permission(owner_firm_perm(:find, Report, firms(:mertz))) do
      assert @mertz_billing.users_permitted_to(:find).include?( User.current )
      assert !@ricardo_billing.users_permitted_to(:find).include?(User.current)
    end
  end

  # Verify that we *can't* set permissions on derived classes...

  def test_derived_class_permissions_invalid
    p = wildcard_perm( :find, BillingReport )
    assert !p.valid?
    assert_match /STI base/, p.errors.on('class_name')
  end


end

