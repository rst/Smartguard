#--
# Copyright (c) 2007 Robert S. Thau, Smartleaf, Inc.
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

class RoleAssignmentTest < ActiveSupport::TestCase

  use_all_fixtures

  def test_validations

    ra = RoleAssignment.new

    assert_requires( one_object_perm( :administer, users(:lucy))) do
      do_test_required_associate ra, :user, users(:lucy)
    end

    assert_requires( one_object_perm( :assign, roles(:ricardo_twiddler))) do
      do_test_required_associate ra, :role, roles(:ricardo_twiddler)
    end

    assert_valid ra
    assert ra.save

  end

  def test_update_pchecks
    User.as( users( :universal_grant_guy )) do

      ra = RoleAssignment.new
      ra.role = roles(:ricardo_twiddler)
      ra.user = users(:ricky)
      ra.save!

      assert ra.save

      assert_raises(PermissionFailure) { ra.role    = roles(:ricardo_admin) }
      assert_raises(PermissionFailure) { ra.user    = users(:lucy) }
      assert_raises(PermissionFailure) { ra.role_id = roles(:ricardo_admin).id}
      assert_raises(PermissionFailure) { ra.user_id = users(:lucy).id }
      
    end
  end

  def test_current

    ra = RoleAssignment.new
    assert ra.current?

    ra.invalid_after = Time.now + 15
    assert ra.current?

    ra.invalid_after = Time.now - 15
    assert !ra.current?

  end

end
