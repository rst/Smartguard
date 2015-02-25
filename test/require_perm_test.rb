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

class PhonyBlog < ActiveRecord::Base

  self.table_name = 'blogs'        # already exists; what the hell...

  include Access::Controlled
  owner_attrs_and_validations :include_privs => false
  
  # Some attributes.  NB these don't have to come out of the DB
  # directly for AR's update_attribute and friends to deal with 'em...

  attr_accessor :attr_unguarded, :attr_all_guarded_grab, :attr_set_guarded_grub

  # A few guarded methods, with guards declared
  # after the method definitions.

  def foo; "invoked foo" end
  def bar( arg ); "invoked bar with #{arg.inspect}" end

  require_privilege :grubbitz, 
    :to_invoke => [:foo, :moo],
    :to_set_attribute => :attr_set_guarded_grub
                            
  require_privilege :grabbitz, 
    :to_invoke => :bar,
    :to_access_attribute => :attr_all_guarded_grab

  require_privilege :change_name, :to_set_attribute => :name

  declare_privilege :bleat, :meow, :grubbitz
  declare_privilege :bleat, :meow

  # Another guarded method, with a guard declared
  # before the method definition.

  def moo( arg )
    yield arg + ', but I am a cow!'
  end

  def unguarded_set_attrs_for_copy!(attrs)
    smartguard_set_attrs_for_copy!(attrs)
  end

end

class PhonyNoPerms < ActiveRecord::Base

  self.table_name = 'blogs'        # already exists; what the hell...

  include Access::Controlled
  owner_attrs_and_validations :include_privs => false

end

class PhonyWithCallbacks < ActiveRecord::Base

  self.table_name = 'blogs'

  include Access::Controlled
  owner_attrs_and_validations

  require_privilege :create,  :at_callback => :before_create
  require_privilege :find,    :at_callback => :after_find
  require_privilege :update,  :at_callback => :before_update
  require_privilege :destroy, :at_callback => :before_destroy

end

class PhonyWithEponymous < ActiveRecord::Base

  self.table_name = 'blogs'

  include Access::Controlled
  owner_attrs_and_validations

  require_eponymous_privilege_to :find
  require_eponymous_privilege_to :create, :update, :destroy

end

class PhonyWithForAction < ActiveRecord::Base

  self.table_name = 'blogs'

  include Access::Controlled
  owner_attrs_and_validations

  require_privilege :find,    :for_action => :find
  require_privilege :create,  :for_action => :create
  require_privilege :update,  :for_action => :update
  require_privilege :destroy, :for_action => :destroy

end

class PhonyWithInitSet < ActiveRecord::Base

  self.table_name = 'blogs'

  include Access::Controlled
  owner_attrs_and_validations

  attr_accessor :init_guarded, :update_guarded, :set_guarded, :access_guarded

  require_privilege :priv,
    :to_initialize_attribute => :init_guarded,
    :to_update_attribute     => :update_guarded,
    :to_set_attribute        => :set_guarded,
    :to_access_attribute     => :access_guarded

end

class PhonyNeverPermits < ActiveRecord::Base

  self.table_name = 'blogs'

  include Access::Controlled
  owner_attrs_and_validations :include_privs => false

  never_permit_anyone :to_update_attribute => :name

end

class PhonyWithDefaults < ActiveRecord::Base

  self.table_name = 'blogs'

  include Access::Controlled
  owner_attrs_and_validations :default_from_current_user => true

end

# The following three exist solely for the sake of test_permits_create,
# which tweaks them in the course of running the test...

class PhonyReqPermBlog < ActiveRecord::Base
  self.table_name = 'blogs'
  include Access::Controlled
end

class PhonyReqPermEntry < ActiveRecord::Base

  self.table_name = 'blog_entries'
  include Access::Controlled
  belongs_to :blog, :class_name => 'PhonyReqPermBlog', 
                    :foreign_key => 'blog_id'

  require_privilege :dribble, :to_associate_as => 'PhonyReqPermComment#entry'

end

class PhonyReqPermComment < ActiveRecord::Base
  self.table_name = 'entry_comments'
  include Access::Controlled
  belongs_to :entry, :class_name => 'PhonyReqPermEntry',
                     :foreign_key => 'blog_entry_id'
end

class RequirePermTest < ActiveSupport::TestCase

  use_all_fixtures

  def test_declare_permission
    expected_privs = [:bleat, :change_name, :grabbitz, :grubbitz, :meow] +
                     Access::RequirePrivilege::DEFAULT_DECLARED_PRIVILEGES
    assert_equal expected_privs,
      PhonyBlog.declared_privileges.sort_by( &:to_s )
    assert_equal Access::RequirePrivilege::DEFAULT_DECLARED_PRIVILEGES, 
      PhonyNoPerms.declared_privileges
    assert_raises( ArgumentError ) do
      PhonyBlog.declare_privilege 'a string, not a symbol'
    end
  end

  def test_require_permission_invoke

    my_phony = nil

    assert_requires(owner_perm(:change_name, PhonyBlog, users(:lucy))) do
      my_phony = PhonyBlog.create! :owner => users(:lucy),
        :owner_firm => firms(:ricardo), :name => "FunkyBlog"
      assert_equal "FunkyBlog", my_phony.name
    end

    assert_requires( one_object_perm( :grubbitz, my_phony )) do
      assert_equal "invoked foo", my_phony.foo 
    end

    assert_requires( one_object_perm( :grabbitz, my_phony )) do
      assert_equal "invoked bar with true", my_phony.bar( true )
      assert_equal "invoked bar with 5738", my_phony.bar( 5738 )
    end

    assert_requires( one_object_perm( :grubbitz, my_phony )) do
      foo = 3
      my_phony.moo( 'bark' ) { |arg| foo = arg }
      assert_equal 'bark, but I am a cow!', foo
    end

  end

  def test_rails_attrs

    # These go through method_missing every time?  Ay caramaba!
    # So, for now, they're never actually defined, and special
    # hacks are needed to make the following work.

    my_phony = PhonyBlog.new :owner => users(:lucy), 
      :owner_firm => firms(:ricardo)

    assert_requires(owner_perm(:change_name, PhonyBlog, users(:lucy))) do
      my_phony.name = "FunkyBlog"
      assert_equal "FunkyBlog", my_phony.name
    end

  end

  def test_require_permission_attrs

    # Following sets up a new PhonyBlog in attr_test_phony

    attr_test_phony = nil       # get in scope
    ct = 0

    assert_nil PhonyBlog.reflected_privilege(:update_attribute, 
                                             :attr_unguarded)
    assert_equal :grubbitz, 
      PhonyBlog.reflected_privilege(:update_attribute, :attr_set_guarded_grub)
    assert_equal :grabbitz,
      PhonyBlog.reflected_privilege(:update_attribute, :attr_all_guarded_grab)


    assert_requires( owner_perm( :grubbitz, PhonyBlog, users(:lucy) )) do

      attr_test_phony = PhonyBlog.new :owner => users(:lucy), 
                                      :owner_firm => firms(:ricardo)

      attr_test_phony.attr_unguarded = 'zot'
      assert_equal 'zot', attr_test_phony.attr_unguarded

      attr_test_phony.attr_set_guarded_grub = 'sg1'
      assert_equal 'sg1', attr_test_phony.attr_set_guarded_grub
    end

    assert_nothing_raised do
      assert_equal 'sg1', attr_test_phony.attr_set_guarded_grub
    end

    assert_requires( owner_perm( :grubbitz, PhonyBlog, users(:lucy) )) do
      attr_test_phony.attributes = { :attr_set_guarded_grub => 'sg2' }
    end

    assert_nothing_raised do
      assert_equal 'sg2', attr_test_phony.attr_set_guarded_grub
    end

    assert_requires( owner_perm( :grabbitz, PhonyBlog, users(:lucy) )) do
      attr_test_phony.attr_all_guarded_grab = 'ag1'
    end

    assert_requires( owner_perm( :grabbitz, PhonyBlog, users(:lucy) )) do
      assert_equal 'ag1', attr_test_phony.attr_all_guarded_grab
    end

    # And lastly, check checks on arguments to require_permission itself.

    assert_raises( ArgumentError ) do
      PhonyBlog.require_privilege :foo, :misspelled_keyword => 'whatever'
    end

  end

  # Smoke test for permits_update_attribute? --- actually tested
  # far more, indirectly, by the form tests.

  def test_permits_update_attr

    attr_test_phony = nil

    assert_requires( owner_perm(:change_name, PhonyBlog, users(:lucy))) do
      attr_test_phony = PhonyBlog.create! :owner => users(:lucy), 
                                          :owner_firm => firms(:ricardo),
                                          :name => "phony"
    end

    with_test_role_for_unprivileged_guy(:no_grants) do |user, role|

      assert !attr_test_phony.permits_update_attr?( :attr_set_guarded_grub )
      assert !attr_test_phony.permits_update_attr?( :attr_all_guarded_grab )

      User.as(users(:universal_grant_guy)) do
        role.permissions << one_object_perm( :grubbitz, attr_test_phony )
        user.permissions :force_reload
      end

      assert_equal 1, user.permissions.size

      assert  attr_test_phony.permits_update_attr?( :attr_set_guarded_grub )
      assert !attr_test_phony.permits_update_attr?( :attr_all_guarded_grab )

      assert !attr_test_phony.permits_update_attr?( :attr_set_guarded_grub,
                                                    users(:lucy) )
      
    end

  end

  # Tests for the bypass for copy functionality

  def test_set_attrs_for_copy_unsaved
    with_test_role_for_unprivileged_guy(:no_grants) do |user, role|
      attr_test_phony = PhonyBlog.new
      attr_test_phony.unguarded_set_attrs_for_copy!( :attr_set_guarded_grub =>
                                                     'bozo' )
      assert_equal 'bozo', attr_test_phony.attr_set_guarded_grub
      assert_raises( PermissionFailure ) do
        attr_test_phony.attr_set_guarded_grub = 'clown'
      end
    end
  end

  def test_set_attrs_for_copy_saved
    attr_test_phony = nil

    assert_requires( owner_perm(:change_name, PhonyBlog, users(:lucy))) do
      attr_test_phony = PhonyBlog.create! :owner => users(:lucy), 
                                          :owner_firm => firms(:ricardo),
                                          :name => "phony"
    end

    assert_raises( ArgumentError ) do
      attr_test_phony.unguarded_set_attrs_for_copy!( :attr_set_guarded_grub =>
                                                     'bozo' )
    end
  end

  # Test for permits_create?  Note that we must tweak the classes
  # themselves to easily cover all cases

  def test_permits_create

    with_test_role_for_unprivileged_guy do |user, role|

      assert PhonyReqPermEntry.permits_create?

      PhonyReqPermEntry.require_privilege :blurt, :for_action => :create

      assert !PhonyReqPermEntry.permits_create?

      role.permissions << wildcard_perm( :blurt, PhonyReqPermEntry )
      user.permissions :force_reload

      assert PhonyReqPermEntry.permits_create?

      PhonyReqPermBlog.require_privilege :bloviate,
        :to_associate_as => 'PhonyReqPermEntry#blog'

      assert !PhonyReqPermEntry.permits_create?

      role.permissions << wildcard_perm( :bloviate, PhonyReqPermBlog )
      user.permissions :force_reload

      assert PhonyReqPermEntry.permits_create?

      # And also check that permission to associate is *not* required
      # if the foreign key is permitted to be NULL:

      assert_not_nil PhonyReqPermEntry.associate_privilege( 
             PhonyReqPermComment.name, :entry )

      assert PhonyReqPermComment.permits_create?

    end

    # Lastly, test that we get a permission failure, and not some
    # random NPE-ish crud, when User.current is unset..

    assert_nil User.current
    assert_raise( PermissionFailure ) { PhonyReqPermEntry.permits_create? }

  end

  def test_on_associated
    # For this, we use the permission on the main Blog and BlogEntry 
    # classes

    with_test_role_for_unprivileged_guy do |user, role|
      entry = BlogEntry.new :blog => blogs(:mertz_blog)
      assert_raises( PermissionFailure ) do 
        entry.entry_txt = 'Welcome to the Mertz blog!'
      end
      entry = BlogEntry.new # no blog
      assert_raises( PermissionFailure ) do
        entry.entry_txt = 'Welcome to the Mertz blog!'
      end
    end

    assert_requires( one_object_perm( :change_post, blogs(:mertz_blog) )) do
      entry = BlogEntry.new :blog => blogs(:mertz_blog)
      entry.entry_txt = 'Welcome to the Mertz blog!'
    end

    assert !BlogEntry.declared_privileges.include?( :change_post )

  end

  def test_associate_as

    # Again, we use the stock "pseudo-model" classes.
    # First, just make sure the declarations are properly parsed.

    assert_equal :add_comment,
      BlogEntry.associate_privilege( 'EntryComment', 'blog_entry' )

    assert_equal :kill_comment,
      BlogEntry.dissociate_privilege( 'EntryComment', 'blog_entry' )

    # Now get a couple of BlogEntries to play with.

    my_entry_a = nil
    my_entry_b = nil

    assert_requires( one_object_perm( :change_post, blogs(:mertz_blog) )) do
      my_entry_a = BlogEntry.create! :blog => blogs(:mertz_blog),
        :owner => users(:ethel), :owner_firm => firms(:mertz),
        :entry_txt => 'Mertz blog entry a'
      my_entry_b = BlogEntry.create! :blog => blogs(:mertz_blog),
        :owner => users(:ethel), :owner_firm => firms(:mertz),
        :entry_txt => 'Mertz blog entry b'
    end

    # And try setting up a comment.

    my_comment = nil

    aperm_add  = one_object_perm( :add_comment,  my_entry_a )
    bperm_add  = one_object_perm( :add_comment,  my_entry_b )
    aperm_kill = one_object_perm( :kill_comment, my_entry_a )
    bperm_kill = one_object_perm( :kill_comment, my_entry_b )
    
    assert_requires( aperm_add ) do
      my_comment = EntryComment.create! :blog_entry => my_entry_a,
        :owner => users(:ethel), :owner_firm => firms(:mertz),
        :comment_txt => 'this is a comment'
      assert_equal my_entry_a, my_comment.blog_entry
    end

    assert_requires( aperm_kill, bperm_add ) do
      my_comment.blog_entry = my_entry_b
      assert_equal my_entry_b, my_comment.blog_entry
    end

    assert_requires( bperm_kill, aperm_add ) do
      my_comment.update_attribute :blog_entry, my_entry_a
    end

    assert_requires( aperm_kill, bperm_add ) do
      # NB this does *not* reset (or null out) the actual associate!
      my_comment.blog_entry_id = my_entry_b.id
    end

    assert_nothing_raised do
      # no change, no check
      my_comment.blog_entry_id = my_entry_b.id
    end

    # This will start failing if they fix the bug...
    # assert_equal my_entry_a, my_comment.blog_entry

    assert_requires( bperm_kill, aperm_add ) do
      my_comment.blog_entry = my_entry_a
    end

    assert_requires( aperm_kill ) do
      my_comment.blog_entry = nil
    end

    assert_nil my_comment.blog_entry
    assert_nil my_comment.blog_entry_id

    assert_requires( bperm_add ) do
      my_entry_b.entry_comments << my_comment
    end

    assert_requires( bperm_kill ) do 
      my_comment.destroy
    end

    # Lastly, test that we can set the association to nil

    assert_nothing_raised do
      my_comment = EntryComment.create! :owner => users(:ethel), 
        :owner_firm => firms(:mertz),
        :comment_txt => 'this is a comment'
    end

    assert_requires( aperm_add ) do
      my_comment.blog_entry = my_entry_a
    end

    assert_requires( aperm_kill ) do
      my_comment.blog_entry = nil
    end

  end

  def test_at_callback

    common_callback_test( PhonyWithCallbacks )

    assert_raises( NoMethodError ) do 
      PhonyWithCallbacks.require_privilege :heat, :at_callback => :before_bake
    end

  end

  def test_for_action

    common_callback_test( PhonyWithForAction )

    assert_raises( ArgumentError ) do 
      PhonyWithCallbacks.require_privilege :heat, :for_action => :bake
    end

  end

  def test_eponymous

    common_callback_test( PhonyWithEponymous )

    assert_raises( ArgumentError ) do 
      PhonyWithEponymous.require_eponymous_privilege_to :baste
    end

  end

  def common_callback_test( phklass )

    assert_equal :create,  phklass.callback_privilege( :before_create )
    assert_equal :find,    phklass.callback_privilege( :after_find )
    assert_equal :update,  phklass.callback_privilege( :before_update )
    assert_equal :destroy, phklass.callback_privilege( :before_destroy )

    my_phony = phklass.new :name => 'phony blog', :owner => users(:lucy),
      :owner_firm => firms(:ricardo)

    # Create require :create permission; it should fail and do nothing
    # even with update permission.

    phtotal = phklass.count

    assert_fails_even_with owner_perm(:update, phklass, users(:lucy)) do
      my_phony.save
    end

    assert_equal phtotal, phklass.count

    with_test_role_for_unprivileged_guy do |user, role|
      [:before_create, :after_find, 
       :before_update, :before_destroy].each do |callback|
        assert !my_phony.permits_at_callback?( callback )
      end
      [:create, :find, :update, :destroy].each do |event|
        assert !my_phony.permits_action?( event )
      end
    end

    assert_requires owner_perm(:create, phklass, users(:lucy)) do
      my_phony.save
      assert my_phony.permits_at_callback?( :before_create )
      assert my_phony.permits_action?( :create )
    end

    assert_equal phtotal + 1, phklass.count

    # Access privilege should be required for reload or find

    assert_requires owner_perm(:find, phklass, users(:lucy)) do
      my_phony.reload
    end

    assert_requires owner_perm(:find, phklass, users(:lucy)) do
      phklass.find my_phony.id
      assert my_phony.permits_at_callback?( :after_find )
      assert my_phony.permits_action?( :find )
    end

    # Update should fail and do nothing even with create privilege

    my_phony.name = 'phony blog updated'

    assert_fails_even_with owner_perm(:create, phklass, users(:lucy)) do
      my_phony.save
    end

    assert_requires owner_perm(:find, phklass, users(:lucy)) do
      assert_equal 'phony blog', (phklass.find my_phony.id).name
    end

    # But should work with update privilege

    assert_requires owner_perm(:update, phklass, users(:lucy)) do
      my_phony.save
      assert my_phony.permits_at_callback?( :before_update )
      assert my_phony.permits_action?( :update )
    end

    assert_requires owner_perm(:find, phklass, users(:lucy)) do
      assert_equal 'phony blog updated', (phklass.find my_phony.id).name
    end

    # Delete should fail and do nothing without privs...

    assert_fails_even_with owner_perm(:update, phklass, users(:lucy)) do
      my_phony.destroy
    end

    assert_equal phtotal + 1, phklass.count

    # And work with appropriate privilege

    assert_requires owner_perm(:destroy, phklass, users(:lucy)) do
      my_phony.destroy
      assert my_phony.permits_at_callback?( :before_destroy )
      assert my_phony.permits_action?( :destroy )
    end

    assert_equal phtotal, phklass.count
    assert_raises( ActiveRecord::RecordNotFound){ phklass.find( my_phony.id ) }

  end

  def test_permits_action_delete
    with_test_role_for_unprivileged_guy(:no_grants) do |user, role|

      test_ra = role_assignments(:ricky_ricardo_admin)

      assert_equal users(:ricky), test_ra.user
      assert !users(:ricky).permits?( :administer )
      assert !test_ra.permits_action?( :destroy )

      User.as( users(:universal_grant_guy) ) do
        role.permissions << one_object_perm( :administer, users(:ricky) )
        user.permissions :force_reload
      end

      assert test_ra.permits_action?( :destroy )
      
    end
  end

  def test_on_set_on_initialize

    [:init_guarded, :set_guarded, :access_guarded].each do |attr|
      assert_requires( wildcard_perm( :priv, PhonyWithInitSet )) do
        PhonyWithInitSet.new attr => 'foo'
      end
    end

    assert_nothing_raised do
      PhonyWithInitSet.new :update_guarded => 'foo'
    end

    my_phony = PhonyWithInitSet.create! :name => 'phony blog', 
      :owner => users(:lucy),
      :owner_firm => firms(:ricardo)

    assert !my_phony.new_record?

    [:update_guarded, :set_guarded, :access_guarded].each do |attr|
      assert_requires( wildcard_perm( :priv, PhonyWithInitSet )) do
        my_phony.attributes = { attr => 'foo' }
      end
    end

    assert_nothing_raised do
      my_phony.attributes = { :init_guarded => 'foo' }
    end

  end

  def test_update_attr_reflection
    User.as( users( :lucy )) do

      frob = PhonyWithInitSet.new :owner => users(:lucy), 
        :owner_firm => firms(:ricardo), :name => 'dummy'

      assert_equal :priv, frob.initialize_attr_privilege( :init_guarded )
      assert_equal :priv, frob.update_attr_privilege( :update_guarded )
      assert_nil frob.initialize_attr_privilege( :update_guarded )
      assert_nil frob.update_attr_privilege( :init_guarded )

      assert_equal :priv, frob.set_attr_privilege( :init_guarded )
      assert_nil          frob.set_attr_privilege( :update_guarded )

      frob.save!

      assert_nil          frob.set_attr_privilege( :init_guarded )
      assert_equal :priv, frob.set_attr_privilege( :update_guarded )
      
    end
  end

  def test_never_permit

    assert_equal Access::RequirePrivilege::DEFAULT_DECLARED_PRIVILEGES, 
       PhonyNeverPermits.declared_privileges

    my_phony = PhonyNeverPermits.create! :name => 'phony blog', 
      :owner => users(:lucy),
      :owner_firm => firms(:ricardo)

    User.as( users(:ricky )) do
      assert_raises( PermissionFailure ) do
        my_phony.name = 'not phony blog'
      end
    end
    
    assert_equal :forbidden_operation, 
      my_phony.set_attr_privilege( :name )

    assert_raises( ArgumentError ) do
      PhonyNeverPermits.never_permit_anyone :to_access_attribute => :owner_id
    end

  end

  def test_wildcards_dont_allow_forbidden_operations

    my_np = PhonyNeverPermits.first

    with_permission( wildcard_perm( :any, PhonyNeverPermits )) do
      assert_equal [], PhonyNeverPermits.all_permitting( :forbidden_operation )
      assert_raises( PermissionFailure ) do
        my_np.name = 'glorp'
      end
    end
  end

  def test_owner_defaults

    User.as( users( :lucy )) do

      obj = PhonyWithDefaults.new
      obj.valid?

      assert_equal users(:lucy),    obj.owner
      assert_equal firms(:ricardo), obj.owner_firm

      obj = PhonyWithDefaults.new :owner      => users(:fred), 
                                  :owner_firm => firms(:mertz)
    
      obj.valid?
      assert_equal users(:fred),  obj.owner
      assert_equal firms(:mertz), obj.owner_firm

      obj = PhonyWithDefaults.new :owner_id      => users(:fred).id, 
                                  :owner_firm_id => firms(:mertz).id
    
      obj.valid?
      assert_equal users(:fred),  obj.owner
      assert_equal firms(:mertz), obj.owner_firm

      assert_raises( ArgumentError ) do
        Blog.owner_attrs_and_validations :default_from_misspelled_arg => true
      end

    end

  end

  # Testing where_permits_action and where_permits_update_attr ---
  # simple cases.

  def test_where_permits_action
    User.as( users( :fred )) do
      assert_equal PhonyWithEponymous.where_permits( :create ),
        PhonyWithEponymous.where_permits_action( :create )
      assert_equal '1 = 1', PhonyNoPerms.where_permits_action( :create )
    end
  end

  def test_where_permits_update_attr
    User.as( users( :fred )) do
      assert_equal PhonyWithInitSet.where_permits( :priv ),
        PhonyWithInitSet.where_permits_update_attr( :update_guarded )
      assert_equal '1 = 1',       
        PhonyWithInitSet.where_permits_update_attr( :init_guarded )
    end
  end

  # Testing where_permits_action and where_permits_update_attr ---
  # complex cases, involving :on_associated.  Here the SQL comes
  # from a new and funky variant of where_permits, so we actually
  # have to explicitly check that it does the right thing.
  #
  # We similarly check for 'ids_permitting'.  The code for that
  # drives 'where_permits' in almost all cases; this is the one
  # case where 'ids_permitting' adds significant extra machinery,
  # so we check here that that machinery is doing the right thing.

  def test_where_permits_associated

    my_entry = nil
    blog = blogs(:mertz_blog)
    owner = blog.owner
    other_user = users(:lucy)
    
    assert other_user != owner  # 'owner' is really fred; just checking...

    with_permission( wildcard_perm( :change_post, Blog )) do
      my_entry = BlogEntry.create! :blog => blog, :entry_txt => 'foo',
        :owner => blog.owner, :owner_firm => blog.owner_firm
    end

    check_permits_both_ways( owner, other_user ) do | should_it, who |
      assert_access_query_correct(should_it, my_entry, "#{who} upd txt") do
        BlogEntry.where( BlogEntry.where_permits_update_attr( :entry_txt ))
      end

      ids_permitting_qry = BlogEntry.ids_permitting_update_attr( :entry_txt )
      ids = ActiveRecord::Base.connection.select_values( ids_permitting_qry )

      where_permits_cond = BlogEntry.where_permits_update_attr( :entry_txt )
      records = BlogEntry.where( where_permits_cond ).to_a

      assert_equal records.collect(&:id).sort, ids.sort

    end

    check_permits_both_ways( owner, other_user ) do | should_it, who |
      assert_access_query_correct(should_it, my_entry, "#{who} destroy") do
        BlogEntry.where( BlogEntry.where_permits_action( :destroy ))
      end

      ids_permitting_qry = BlogEntry.ids_permitting_action( :destroy )
      ids = ActiveRecord::Base.connection.select_values( ids_permitting_qry )

      where_permits_cond = BlogEntry.where_permits_action( :destroy )
      records = BlogEntry.where( where_permits_cond ).to_a

      assert_equal records.collect(&:id).sort, ids.sort

    end

  end

  def check_permits_both_ways( owner, other_user )

    with_permission( owner_perm( :change_post, Blog, owner )) do
      yield( true, "owner" )
    end
    
    with_permission( owner_perm( :change_post, Blog, other_user )) do
      yield( false, "other" )
    end
    
  end

  def assert_access_query_correct( should_it, item, msg )
    klass = item.class
    items = yield
    if should_it
      assert items.include?( item ), msg
    else
      assert !items.include?( item ), msg
    end
  end

end
