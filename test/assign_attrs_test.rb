#--
# Copyright (c) 2007, 2016 Robert S. Thau, Smartleaf, Inc.
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

class AssignAttrsEntryTest < ActiveSupport::TestCase

  fixtures :users, :firms, :blogs

  def test_block_set_groups

    blog = blogs(:mertz_blog)
    
    # Rig a set of attributes so that simple iteration will try to
    # set 'entry_txt' *before* setting 'blog', even though setting
    # 'blog' is required to get permission to set 'entry_txt'.
    #
    # Block-set groups exist to prevent this...
    #
    # (Relies on Ruby 1.9+ behavior that iteration over hashes goes
    # in insertion order; otherwise, this would be really awkward to
    # write!)

    attrs = {}
    attrs[:entry_txt] = 'Stuff!'
    attrs[:blog] = blog

    assert_equal :entry_txt, attrs.keys.first

    # Make sure that permissions on setting this are enforced, but
    # that it works otherwise...

    assert_requires(one_object_perm(:change_post, blog)) do
      BlogEntry.new(attrs)
    end

    with_permission(one_object_perm(:change_post, blog)) do
      assert_nothing_raised do
        it = BlogEntry.new(attrs)
        assert_equal 'Stuff!', it.entry_txt
        assert_equal blog, it.blog
      end
    end

  end

  def test_strong_parameters
    # We want to make sure that if we have unpermitted controller
    # 'params' feeding into assign_attributes, the proper exception
    # is raised, and *nothing* gets set.

    bad_params = ActionController::Parameters.new(blog: blogs(:mertz_blog),
                                                  entry_txt: 'foo')

    my_entry = BlogEntry.new
    orig_attrs = my_entry.attributes.clone

    assert_raise ActiveModel::ForbiddenAttributesError do
      my_entry.attributes = bad_params
    end
    
    assert_equal orig_attrs, my_entry.attributes

  end

end
