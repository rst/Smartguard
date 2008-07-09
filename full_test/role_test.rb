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

class RoleTest < Test::Unit::TestCase

  use_all_fixtures

  def test_validations

    r = Role.new

    test_validation r, :owner_firm, :invalid => [nil], 
      :valid => [firms(:mertz)]

    test_validation r, :owner, :invalid => [nil], 
      :valid => [users(:ethel)]

    # Name --- we test scoping; Mertz firm has an admin role already, so
    # can't create another, but we can create a 'twiddler' role, even though
    # Ricardo already has one.

    test_validation r, :name, 
      :invalid => ['', 'x', 'ab', 'admin', 'x' * 101],
      :valid   => ['twiddler', 'x' * 100]

    assert_valid r

    assert_requires( owner_firm_perm( :create, Role, firms(:mertz) )) do
      assert r.save
    end

  end

end
