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

class PhonyPatBlog < ActiveRecord::Base

  self.table_name = 'blogs'

  include FullTestAccessControl
  owner_attrs_and_validations

  require_privilege :add_post,  :to_associate_as  => 'PhonyPatEntry#blog'
  require_privilege :kill_post, :to_dissociate_as => 'PhonyPatEntry#blog'

end

class PhonyPatEntry < ActiveRecord::Base

  self.table_name = 'blog_entries'

  include FullTestAccessControl
  owner_attrs_and_validations

  belongs_to :blog, :class_name => 'PhonyPatBlog', :foreign_key => 'blog_id'

  require_eponymous_privilege_to :create, :update

end

class PermittedAssocsTest < ActiveSupport::TestCase

  use_all_fixtures

  Firm.require_privilege :blog_within_firm,
    :to_associate_as => 'PhonyPatEntry#owner_firm'

  def setup

    @patblog = {}
    %w(mertz_blog ricky_dubuque_blog 
       fred_dubuque_blog ethel_dubuque_blog).each do |blog_name|
      blog_name = blog_name.to_sym
      @patblog[ blog_name ] = PhonyPatBlog.find blogs( blog_name ).id
    end

    with_permission([ one_object_perm( :blog_within_firm, firms(:dubuque) ),
                      one_object_perm( :add_post, 
                                       @patblog[ :ricky_dubuque_blog ] ),
                      wildcard_perm( :create, PhonyPatEntry ) ]) do 
      @ricky_entry = PhonyPatEntry.create! :entry_txt => 'hello',
        :owner => users(:ricky),
        :owner_firm => firms(:dubuque),
        :blog => @patblog[ :ricky_dubuque_blog ]
      if @ricky_entry.new_record?
        print "Huh?  save preserves new_record!\n"
      end
    end
  end

  def assert_same_ids( a_set, b_set )
    a_set_ids = a_set.collect( &:id ).sort
    b_set_ids = b_set.collect( &:id ).sort
    assert_equal a_set_ids, b_set_ids
  end

  def test_no_restrictions
    assert_same_ids Firm.all, 
      blogs(:ricky_dubuque_blog).permitted_associates( :owner_firm )
  end

  def test_assoc_dissoc

    assoc_perm  = owner_firm_perm( :add_post,  PhonyPatBlog, firms( :dubuque ))
    dissoc_perm = one_object_perm( :kill_post, @ricky_entry.blog )

    with_permission( assoc_perm ) do
      assert_same_ids [ @ricky_entry.blog ], 
        @ricky_entry.permitted_associates( :blog )
    end

    with_permission( [assoc_perm, dissoc_perm] ) do
      assert_same_ids PhonyPatBlog.where(owner_firm_id: firms(:dubuque)),
        @ricky_entry.permitted_associates( :blog )
    end

  end

  def test_owned_by_self

    perm = wildcard_perm( :create, PhonyPatEntry )
    perm.target_owned_by_self = true

    with_permission( perm ) do
      assert_equal [ User.current.id ], 
                   PhonyPatEntry.new.permitted_associates(:owner).collect(&:id)
    end
    
  end

  def test_at_create

    entry = PhonyPatEntry.new :entry_txt => 'goodbye'

    common_create_update_test( entry, :create, :update )

  end

  def test_at_update

    assert !@ricky_entry.new_record?
    common_create_update_test( @ricky_entry, :update, :create )

  end

  def common_create_update_test( entry, event, nonevent )

    blog_perm_dubuque = one_object_perm( :blog_within_firm, firms(:dubuque) )
    blog_perm_shire   = one_object_perm( :blog_within_firm, firms(:shire) )

    event_perm_dubuque = owner_firm_perm( event, PhonyPatEntry, 
                                          firms(:dubuque) )
    event_perm_shire   = owner_firm_perm( event, PhonyPatEntry, 
                                          firms(:shire) )

    nonevent_perm_dubuque = owner_firm_perm( nonevent, PhonyPatEntry,
                                             firms(:dubuque) )

    with_permission( blog_perm_dubuque ) do
      assert_equal [], entry.permitted_associates( :owner_firm )
    end

    with_permission( event_perm_dubuque ) do
      assert_equal [], entry.permitted_associates( :owner_firm )
    end

    with_permission( [blog_perm_dubuque, nonevent_perm_dubuque] ) do
      assert_equal [], entry.permitted_associates( :owner_firm )
    end

    with_permission( [blog_perm_dubuque, event_perm_dubuque] ) do
      assert_same_ids [ firms(:dubuque) ], 
        entry.permitted_associates( :owner_firm )
    end

    with_permission( [blog_perm_dubuque, event_perm_dubuque,
                      blog_perm_shire] ) do
      assert_same_ids [ firms(:dubuque) ], 
        entry.permitted_associates( :owner_firm )
    end

    with_permission( [blog_perm_dubuque, event_perm_dubuque,
                      blog_perm_shire,   event_perm_shire] ) do
      assert_same_ids [ firms(:dubuque), firms(:shire) ], 
        entry.permitted_associates( :owner_firm )
    end

  end

end
