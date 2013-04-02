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

class BlogTest < ActiveSupport::TestCase

  use_all_fixtures

  def test_validations

    b = Blog.new

    do_test_validation b, :owner_firm, :invalid => [nil], 
      :valid => [firms(:mertz)]
    do_test_validation b, :owner, :invalid => [nil], 
      :valid => [users(:ethel)]

    # Name --- we test scoping; unique only within "firms"

    do_test_validation b, :name, 
      :invalid => [nil, '', 'x', 'ab', 'mertz family blog', 'x' * 101],
      :valid   => ['ricardo family blog', 'x' * 100]

    assert_valid b
    assert b.save

  end
end
