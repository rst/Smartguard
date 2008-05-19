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

class PermissioningTest < Test::Unit::TestCase

  use_all_fixtures

  # Tweaking a permission in any of the following ways should
  # keep it from granting access.

  ACCESS_BLOCKING_TWEAKS = { 
    :privilege  => :blurfl,
    :class_name => 'Role',      # Should be some other, AR::Base nonce class
    :is_grant   => true
  }

  # This permission tweak should *not* prevent granting access.
  
  ACCESS_GRANTING_TWEAKS = {
    :privilege  => :any
  }

  # days to use for testing role assignment expiration

  EXPIRED_IF_INVALID_AFTER = [0, 1].collect { |x| x.days.ago }
  CURRENT_IF_INVALID_AFTER = [1, 2].collect { |x| x.days.from_now } + [ nil ]

  # :call-seq:
  #   with_access_blocking_tweaks( perm ) { |msg| ... }
  #
  # This function tweaks the permission 'perm' in several ways
  # that should all prevent it from granting access, yielding to
  # its block after each.  The block should check that access is,
  # in fact, blocked.  
  #
  # The block is invoked with one argument --- a message describing
  # how the permission was tweaked, which may be useful in explaining
  # test failures.

  def with_access_blocking_tweaks( perm )
    with_tweaks( perm, ACCESS_BLOCKING_TWEAKS, 'failed to block' ) do |msg| 
      yield msg 
    end
  end

  # :call-seq:
  #   with_access_blocking_tweaks( perm ) { |msg| ... }
  #
  # This function tweaks the permission 'perm' in several ways
  # that still allow it to grant access, yielding to its block
  # after each.  The block should check that access is,
  # in fact, granted.  (One such condition is that the permission
  # is not tweaked at all).
  #
  # The block is invoked with one argument --- a message describing
  # how the permission was tweaked, which may be useful in explaining
  # test failures.

  def with_access_granting_tweaks( perm )
    with_tweaks( perm, ACCESS_GRANTING_TWEAKS, 'testing grant of' ) do |msg| 
      yield msg 
    end
    yield 'testing grant of access with no changes' # test with no tweaks
  end

  def with_tweaks( perm, tweaks, what_doing )
    msg_base = what_doing + ' access with '
    tweaks.each do | attr, tweaked_val |
      old_val = perm.send attr
      perm.send( ((attr.to_s + '=').to_sym), tweaked_val )
      perm.save_without_validation
      msg = msg_base + attr.to_s + ' = ' + tweaked_val.to_s
      begin
        yield msg
      ensure
        perm.update_attributes! attr => old_val
      end
    end
  end

  # :call-seq:
  #   with_expired_role_assignment( user, role ) { ... }
  #
  # Finds the assignment of the given role to the given user
  # (which must already exist).  Sets the 'invalid_after' date
  # to values which should already mark it as expired, and
  # yields to its block after each.

  def with_expired_role_assignment( user, role )
    with_dated_role_assignment( user, role, EXPIRED_IF_INVALID_AFTER ) {yield}
  end

  # :call-seq:
  #   with_expired_role_assignment( user, role ) { ... }
  #
  # Finds the assignment of the given role to the given user
  # (which must already exist).  Sets the 'invalid_after' date
  # to values which should *not* mark it as expired, and
  # yields to its block after each.  (No expiry date is one
  # such condition).

  def with_current_role_assignment( user, role )
    with_dated_role_assignment( user, role, CURRENT_IF_INVALID_AFTER ) {yield}
  end

  def with_dated_role_assignment( user, role, expiry_dates )
    assignment = user.role_assignments.find :first,
                   :conditions => ['role_id = ?', role]
    assert_not_nil assignment   # If this fails, bug in the test code.
    old_expiry_date = assignment.invalid_after
    begin
      expiry_dates.each do |date|
        assignment.update_attributes! :invalid_after => date
        yield
      end
    ensure
      assignment.update_attributes! :invalid_after => old_expiry_date
    end
  end

  # Test the roles and role_assignments associations on User,
  # and the permissions pseudo-association.
  #
  # In particular, we test behavior when a role_assignment is
  # expired; the role_assignment itself should still be visible,
  # for UI and reporting purposes; but it should *not* drag the
  # role or its permissions into view.

  def test_user_associations

    user = users(:unprivileged_guy)

    mertz_permissions   = roles(:mertz_admin)  .permissions.sort_by &:id
    ricardo_permissions = roles(:ricardo_admin).permissions.sort_by &:id
    mixed_permissions = (mertz_permissions + ricardo_permissions).sort_by &:id

    user_current_permissions = lambda { 
      user.permissions( :force_reload ).sort_by &:id
    }

    assert_equal [], user_current_permissions.call
    assert_equal 0,  user.roles.count

    User.as( users( :universal_grant_guy)) do
      user.roles << roles(:mertz_admin)
      assert_equal mertz_permissions, user_current_permissions.call
      assert_equal 1,                 user.roles.count

      user.roles << roles(:ricardo_admin)
      assert_equal mixed_permissions, user_current_permissions.call
      assert_equal 2,                 user.roles.count
    end

    # Expiration date in the future shouldn't affect anything.

    with_current_role_assignment( user, roles(:mertz_admin) ) do
      assert_equal mixed_permissions, user_current_permissions.call
      assert_equal 2,                 user.roles.count
    end

    # Expire one assignment.  The expired role assignment should still be
    # visible, but the role should no longer count as one of the user's
    # current roles.

    with_expired_role_assignment( user, roles(:mertz_admin) ) do
      assert_equal 1,                   user.roles.count
      assert_equal 2,                   user.role_assignments.count
      assert_equal ricardo_permissions, user_current_permissions.call
    end

  end

  def test_grant_permissions
    assert_not_equal [], users(:ricky).permissions
    assert_equal     [], users(:ricky).grant_permissions
    assert_not_equal [], users(:universal_grant_guy).permissions
    assert !users(:universal_grant_guy).permissions.all?( &:is_grant? )
    assert users(:universal_grant_guy).grant_permissions.all?( &:is_grant? )
  end

  def test_could_ever
    with_test_role_for_unprivileged_guy do |user, role|

      assert !user.could_ever?( :post, Blog )
      assert !user.could_ever?( :post, 'Blog' )
      
      role.permissions << blog_post_permission( :target_owned_by_self => true )
      user.permissions :force_reload

      assert  user.could_ever?( :post, Blog )
      assert !user.could_ever?( :grok, Blog )

      role.permissions << blog_post_permission( :target_owned_by_self => true,
                                                :privilege => :any )
      assert_equal 2, role.permissions.count
      user.permissions :force_reload
      
      assert  user.could_ever?( :post, Blog )
      assert  user.could_ever?( :grok, Blog )
      assert  user.could_ever?( :post, 'Blog' )
      assert  user.could_ever?( :grok, 'Blog' )

    end
  end

  # Test Permission#grants, to see if it behaves right in the
  # in-core cases.  Having done this, we validate the bulk queries
  # later on against the in-core behavior, and against a larger
  # set of possible examples.

  def test_allows

   User.as( users( :universal_grant_guy )) do

    # XXX need to test combinations of these...

    simple_allow_test users(:lucy), 
                      { :target_owner => users(:lucy) },
                      { :owner        => users(:lucy) },
                      { :owner        => users(:fred) }
                       
    simple_allow_test users(:lucy), 
                      { :target_owner_firm  => firms(:dubuque) },
                      { :owner_firm         => firms(:dubuque) },
                      { :owner_firm         => firms(:mertz) }

    simple_allow_test users(:lucy), 
                      { :target_owned_by_self => true },
                      { :owner        => users(:lucy) },
                      { :owner        => users(:fred) }

    # one_permission targets are, regrettably, a special case...

    perm = blog_post_permission :target => blogs(:mertz_blog),
       :role => roles(:ricardo_twiddler)

    with_access_granting_tweaks( perm ) do |msg|
      assert perm.allows?(blogs(:mertz_blog),:post,users(:fred))
    end

    with_access_blocking_tweaks( perm ) do |msg|
      assert !perm.allows?(blogs(:mertz_blog),:post,users(:fred))
    end

    other_blog = Blog.create :name => "Ricardo blog"

    assert !perm.allows?( other_blog, :post, users(:fred) )

   end

  end
                       
  def simple_allow_test( user, perm_attrs,
                         grant_obj_attrs, block_obj_attrs )

    perm = blog_post_permission( perm_attrs.merge( :role => 
                                                     roles(:ricardo_twiddler)))

    assert_valid perm

    blog = Blog.new grant_obj_attrs

    with_access_granting_tweaks( perm ) do |msg|
      assert perm.allows?( blog, :post, user ), msg
    end

    with_access_blocking_tweaks( perm ) do |msg|
      assert !perm.allows?( blog, :post, user ), msg
    end

    blog.attributes = block_obj_attrs

    if perm.allows?( blog, :post, user )
      STDERR.print "failure for ", perm_attrs.inspect, ", object:\n  ",
        blog.inspect, "\n w/perm\n  ",
        perm.inspect, "\n  after attrs = ", block_obj_attrs.inspect, "\n"
    end

    assert !perm.allows?( blog, :post, user )

  end

  # Make sure that classes with a nonstandard owner_access_key function
  # as intended.  Our guinea pig is the User class, which has a nonstandard
  # owner_access_key --- it's 'id', so that owned_by_self permissions can
  # grant users selective access to their own passwords, preferences, etc.

  def test_owner_access_key

    assert_equal 'id', User.owner_access_control_key

    with_test_role_for_unprivileged_guy( :no_grants ) do |user, role|

      assert !user.can?( :frammis, user )
      assert_equal 0, User.count_permitting( :frammis )

      User.as( users( :universal_grant_guy )) do
        role.permissions << self_owner_perm( :any, User )
        user.permissions :reload
      end

      assert user.can?( :frammis, user )
      assert_equal 1, User.count_permitting( :frammis )
      assert_equal user, User.all_permitting( :frammis ).first
      
    end

  end

  # Test bulk queries ('all_permitting', 'count_permitting').
  # We create a bunch of objects, determine which subsets we should
  # have permission on from various permissions, and verify that that
  # is what comes out.

  def test_grant_queries

    all_my_blogs = []
    base_flags = { :owner_firm => firms(:dubuque) }

    with_test_role_for_unprivileged_guy do |luser, role|

      [ luser, users(:lucy), users(:ricky) ].each do |user|
        flags = base_flags.merge :owner => user
        [ :ricardo, :dubuque ].each do |firm_name|
          flags[:owner_firm] = firms(firm_name)
          flags[:name]       = "blog " + Blog.count.to_s
          blog = Blog.create flags
          all_my_blogs << blog
        end
      end

      perms_sets = 
      [[all_my_blogs.select { |blog| blog.owner == users(:lucy) },
        blog_post_permission( :target_owner => users(:lucy))],

       [all_my_blogs.select { |blog| blog.owner_firm == firms(:ricardo) },
        blog_post_permission( :target_owner_firm  => firms(:ricardo))
       ],

       [all_my_blogs.select { |blog| blog.owner == luser },
        blog_post_permission( :target_owned_by_self => true ) ],

       [[ blogs(:mertz_blog) ],
        blog_post_permission( :target => blogs(:mertz_blog) )]]

      # Slap copies of all permissions onto an irrelevant role
      # to make sure that it's only the roles (and their permissions)
      # assigned to *our* user that make a difference...

      perms_sets.each do |perms_set|
        roles(:ricardo_twiddler).permissions << perms_set.last.clone
      end

      # Actual tests:

      perms_sets.each do |perms_set|
        assert_grant_queries_work_one_perm :post, luser, role, 
          perms_set.first, perms_set.last
      end

      perms_sets.each_with_index do |perms_set_a, i|
        perms_sets.each_with_index do |perms_set_b, j|
          if i != j
            assert_perms_work_in_combination :post, luser, role,
              perms_set_a.first + perms_set_b.first,
              [ perms_set_a.last, perms_set_b.last ]
          end
        end
      end

    end

  end

  # Tests bulk grant permissions: a role with the permission 'perm'
  # should grant its privilege on all the given recs (must have been
  # previously saved, or be fixtures), and no others.

  def assert_grant_queries_work_one_perm( op, user, role, recs, perm )

    perm = perm.clone           # work on a scratch copy

    assert_not_equal 0, recs.size
    assert perm.allows?( recs.first, op, User.current )

    # First, verify that the supposedly unprivileged user doesn't
    # have any permissions floating around that could screw us up.

    assert_equal 0, role.permissions.size # get paranoid about test helpers
    assert_equal roles(:universal_grant).permissions.collect(&:id).sort,
                 user.permissions.collect(&:id).sort

    klass = recs.first.class
    assert_equal 0, (klass.count_permitting op)

    recs.each do |rec|
      assert !(rec.permits? op)
    end

    # Now, assign our permission to the user's (empty) role.

    perm.role = role
    perm.save!

    user.permissions :force_reload
      
    ug_permissions = roles(:universal_grant).permissions

    assert_equal ([perm] + ug_permissions).collect(&:id).sort,
                 user.permissions.collect(&:id).sort

    # If the access_blocking_tweaks are applied to our permission,
    # it still shouldn't grant access.

    with_access_blocking_tweaks( perm ) do |msg|
      assert_equal 0, (klass.count_permitting op), msg
      user.permissions :force_reload
      assert !user.can?( op, recs.first )
    end

    with_access_granting_tweaks( perm ) do |msg|

      # If the role is expired, we shouldn't grant access either.

      with_expired_role_assignment( user, role ) do
        assert_equal 0, (klass.count_permitting op), msg + ' in expired role'
      end

      # But if the role is current, we should get all of our
      # records out of 'klass.all_permitting', and the right 
      # number out of 'klass.count_permitting'.

      with_current_role_assignment( user, role ) do

        assert_equal recs.size, (klass.count_permitting op), msg

        assert_equal (recs.sort_by &:id), 
                     ((klass.all_permitting op).sort_by &:id),
                     msg

        # Verify that the SQL and the in-core permits stuff 
        # do the same thing for all available records.

        rec_ids = recs.collect &:id
        user.permissions :force_reload

        (klass.find :all).each do |rec|
          if rec_ids.include?( rec.id )
            assert rec.permits?( op ), msg
          else
            assert !rec.permits?( op ), msg
          end
        end
      end
    end

    # Don't leave our permission around to mess up the next run.
    
    perm.destroy
    user.permissions :force_reload

  end

  def assert_perms_work_in_combination( op, user, role, recs, perms )

    perms = perms.collect &:clone # work on scratch copies

    perms.each { |perm| perm.role = role; perm.save! }

    ug_perms = roles(:universal_grant).permissions

    user.permissions :force_reload
    assert_equal ((perms + ug_perms).sort_by &:id), 
                 (user.permissions.sort_by &:id)

    klass = recs.first.class
    granted_ids = (klass.all_permitting op).collect &:id

    rec_ids = (recs.collect &:id).sort.uniq
    assert_equal rec_ids.sort, granted_ids.sort

    (klass.find :all).each do |rec|
      if granted_ids.include?( rec.id )
        assert  perms.any? {|perm| perm.allows?( rec, op, user )}
        assert  user.can?( op, rec )
      else
        assert !perms.any? {|perm| perm.allows?( rec, op, user )}
        assert !user.can?( op, rec )
      end
    end

    perms.each { |perm| perm.destroy }
    user.permissions :force_reload

  end

  # Testing the low-level superstructure around the basic engine

  def test_permission_failure_class

    err = PermissionFailure.new "bogon", :target => blogs(:mertz_blog),
                                         :privilege => :grok
    assert err.is_a?( PermissionFailure )
    assert err.is_a?( SecurityError )
    assert_equal :grok,              err.privilege
    assert_equal "bogon",            err.message
    assert_equal Blog,               err.target_class
    assert_equal blogs(:mertz_blog), err.target

    err = PermissionFailure.new "bogon2", :target_class => Blog,
                                          :privilege => :grok
    assert err.is_a?( PermissionFailure )
    assert err.is_a?( SecurityError )
    assert_equal :grok,              err.privilege
    assert_equal "bogon2",           err.message
    assert_equal Blog,               err.target_class
    assert_nil                       err.target

  end

  def test_check_permission
    with_test_role_for_unprivileged_guy do |user, role|

      assert_raises( PermissionFailure ) do
        blogs(:mertz_blog).check_permission!( :grok )
      end

      begin
        blogs(:mertz_blog).check_permission!( :grok )
      rescue
        err = $!
        assert err.is_a?( PermissionFailure )
        assert_equal "not authorized to grok", err.message
        assert_equal :grok,                    err.privilege
        assert_equal blogs(:mertz_blog),       err.target
        assert_equal Blog,                     err.target_class
      end

      perm =
        Permission.new( :privilege    => :grok,
                        :class_name   => 'Blog',
                        :is_grant         => false,
                        :has_grant_option => false,
                        :target_owned_by_self => false,
                        :target       => blogs(:mertz_blog)
                        )

      assert perm.allows?( blogs(:mertz_blog), :grok, user )

      role.permissions << perm
      user.permissions :force_reload

      assert_nothing_raised do
        # When no errors raised, check_permission! returns self...
        assert_equal blogs(:mertz_blog), 
                     blogs(:mertz_blog).check_permission!( :grok )
      end
      
    end
  end

  def test_all_permitting_with_extra_conditions
    with_permission( owner_firm_perm( :post, Blog, firms(:dubuque) )) do

      [nil, 'ric%', 'ricky%'].each do |pat|

        kw_args = {}
        kw_args[:conditions] = ["name like ?", pat] unless pat.nil?

        blogs_by_cond = Blog.find_all_by_owner_firm_id(firms(:dubuque),kw_args)
        blogs_by_perm = Blog.all_permitting( :post, kw_args )

        assert_equal blogs_by_cond.sort_by(&:id), blogs_by_perm.sort_by(&:id)

      end

    end
  end

  def test_permission_save_checks

    new_perm   = blog_post_permission :target_owner => users(:lucy)
    grant_perm = blog_post_permission :target_owner => users(:lucy),
                                      :is_grant => true

    assert_requires( one_object_perm( :edit, roles(:ricardo_twiddler) )) do
      new_perm.role = roles(:ricardo_twiddler)
    end

    klone = new_perm.clone

    assert_requires( grant_perm ) do
      klone.save!
    end
      
    assert_requires( one_object_perm( :edit, roles(:ricardo_twiddler) )) do
      klone.destroy
    end
      
    assert_raises( PermissionFailure ) do 
      User.as( users( :lucy )) do
        new_perm.clone.save! 
      end
    end

    begin
      User.as( users( :lucy )) do
        new_perm.save!
      end
    rescue PermissionFailure
      err = $!
      assert err.is_a?( PermissionFailure )
      assert_equal "not authorized to grant", err.message
      assert_equal :grant,                    err.privilege
      assert_equal new_perm,                  err.target
      assert_equal Permission,                err.target_class
    end

  end

end
