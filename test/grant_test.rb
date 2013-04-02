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
require 'test_helper'

class GrantTest < ActiveSupport::TestCase

  use_all_fixtures

  def test_can_grant

    grant_perm = Permission.new :class_name => 'any', :privilege => :any
    other_perm = Permission.new :class_name => 'any', :privilege => :any
    assert !grant_perm.can_grant?( other_perm )

    grant_perm.is_grant = true
    assert grant_perm.can_grant?( other_perm )

    other_perm.is_grant = true
    assert !grant_perm.can_grant?( other_perm )

    grant_perm.has_grant_option = true
    assert grant_perm.can_grant?( other_perm )

    assert_grant_attr_ok grant_perm, other_perm, :class_name, 'Blog'
    assert_grant_attr_ok grant_perm, other_perm, :privilege, :frammis
    assert_grant_attr_ok grant_perm, other_perm, :target_owned_by_self, true,
      :reset => true

    assert_grant_attr_ok grant_perm, other_perm, :target_owner, users(:ethel)
    assert_grant_attr_ok grant_perm, other_perm, :target_owner_firm, 
                                                                firms(:mertz)

    assert_grant_attr_ok grant_perm, other_perm, :target_id,   7
    assert_grant_attr_ok grant_perm, other_perm, :target_name, 'foo'

  end

  def assert_grant_attr_ok( grant_perm, other_perm, attr, attr_val,
                            options = {}
                            )

    attr_setter = (attr.to_s + '=').to_sym
    unset_val = grant_perm.send attr

    other_perm.send attr_setter, attr_val
    assert grant_perm.can_grant?( other_perm )

    other_perm.send attr_setter, unset_val
    grant_perm.send attr_setter, attr_val
    assert !grant_perm.can_grant?( other_perm )

    other_perm.send attr_setter, attr_val
    assert grant_perm.can_grant?( other_perm )

    if options[:reset]
      grant_perm.send attr_setter, unset_val
      other_perm.send attr_setter, unset_val
    end

  end

end
