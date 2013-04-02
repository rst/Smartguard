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

class PermissionTest < ActiveSupport::TestCase

  use_all_fixtures

  def test_validations

    p = Permission.new

    assert_requires( one_object_perm( :edit, roles(:mertz_admin))) do
      do_test_validation p, :role, :invalid=>[nil], :valid=>[roles(:mertz_admin)]
    end

    [ :is_grant, :has_grant_option, :target_owned_by_self ].each do |attr|
      do_test_validation p, attr, :invalid=>[nil], :valid => [true, false]
    end

    do_test_validation p, :class_name,   
      :invalid => [nil, '', 'raise ArgumentException', 'NoSuchClass', 'Time'],
      :valid   => ['Blog']

    do_test_validation p, :privilege, 
      :invalid => [nil, 'bogon', :foo],
      :valid   => [:post, :grok, :any]

    assert_valid p

    User.as( users( :universal_grant_guy )) do
      assert p.save
    end

  end

  def test_target_class_attr

    p = Permission.new :class_name => 'Blog'
    assert_equal Blog,   p.target_class

    p.target_class = Object
    assert_equal Object, p.target_class

    p.target_class = nil
    assert_nil           p.target_class

    p.class_name   = 'random textual junk'
    assert_raise( NameError ) { p.target_class }

    p.class_name   = 'NoSuchClass'
    assert_raise( NameError ) { p.target_class }

    p.target_class = Object
    assert_equal Object, p.target_class

  end

  def test_target_attr

    p = Permission.new :target_class => Blog
    p.target = blogs(:mertz_blog)

    assert_equal blogs(:mertz_blog).id,   p.target_id
    assert_equal blogs(:mertz_blog).name, p.target_name
    assert_equal blogs(:mertz_blog),      p.target

    p.target = nil

    assert_nil p.target_id
    assert_nil p.target_name
    assert_nil p.target

    assert_raises( ArgumentError ) { p.target = 3 }

  end

end
