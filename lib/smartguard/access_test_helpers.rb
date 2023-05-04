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

module Access
 module TestHelpers

  # :call-seq:
  #   test_validation record, :foo, :invalid => [nil, 'z'], :valid => ['foo']
  #
  # Assigns all of the invalid and valid values to record.foo.
  # Verifies that all of the valid values pass validation, and
  # that the invalid values all flunk.  Leaves the attribute in
  # the last valid state.

  def do_test_validation(rec, field, opts)
    assign = "#{field}="
    opts[:invalid].each do |val|
      rec.send assign, val
      assert !rec.valid?, "#{rec.class} with #{field}=#{val.inspect} should be invalid"
      assert rec.errors.include?(field),
        "#{val.inspect} shouldn't be valid for #{rec.class}.#{field}"
    end
    opts[:valid].each do |val|
      rec.send assign, val
      rec.valid?
      assert !rec.errors.include?(field),
        "#{val.inspect} should be valid for #{rec.class}.#{field}" + 
        "\n(#{rec.errors[field].inspect})"
    end
  end

  # Tests that the record isn't valid if the attribute is unset,
  # and becomes valid if it gets set to the given value.

  def do_test_required_associate(rec, attr, value)
    do_test_validation rec, attr, :invalid => [nil], :valid => [value]
  end

  # :call-seq:
  #   with_test_role_for_unprivileged_guy do |user,role| ... end
  #   with_test_role_for_unprivileged_guy(:no_grants) do |user,role| ... end
  #
  # Helper for auth tests --- runs its block in a dynamic environment
  # in which:
  # 
  # *) User.current is an otherwise unprivileged user
  # *) The user is assigned one role with no privileges.  The user
  #    is also ordinarily assigned the :universal_grant role, so tests
  #    can manipulate its privileges easily.  The :no_grants argument
  #    suppresses even that, and gives a truly unprivileged user; this
  #    is used so that 'assert_requires' can tests privileges of roles.
  #
  # We yield to the block with two arguments:  the user, and its role.
  # A 'ensure' clause undoes any changes.

  def with_test_role_for_unprivileged_guy( no_grants = nil )

    assert( no_grants.nil? || no_grants == :no_grants )

    user = users(:unprivileged_guy)
    role = nil                  # create var in outer scope

    User.as( users(:universal_grant_guy) ) do

      assert_equal 0, user.role_assignments.count

      role = Role.create :name => 'test role', 
        :owner_firm => firms(:dubuque), :owner => user

      RoleAssignment.create :user => user, :role => role

      if !no_grants
        RoleAssignment.create :user => user, :role => roles(:universal_grant)
      end

    end

    user.role_assignments.reload
    user.permissions      :force_reload

    User.as( users(:unprivileged_guy )) do
      yield( user, role )
    end


    User.as( users(:universal_grant_guy) ) do
      role.destroy
      user.role_assignments.reload
      user.role_assignments.each { |ra| ra.destroy }
    end

    user.role_assignments.reload
    assert_equal 0, user.role_assignments.count

    user.permissions :force_reload
    
  end

  # :call-seq:
  #   assert_requires (perm, perm, ...) { code; code ... } 
  #
  # Tests that a role with the all the given permissions correctly grants
  # permission to perform the code in the block.
  # 
  # The priv_or_privs argument may be a single Permission
  # which must grant required access all by itself.  
  #
  # Multiple Permissions may also be given.  In this case, we check
  # that no individual permission is enough to grant the required
  # access, but that collectively, they all do.
  #
  # Argument Permissions are 'dup'ed; the originals are unaltered
  # on return.

  def assert_requires( *priv_or_privs )

    with_test_role_for_unprivileged_guy( :no_grants ) do |user, role|

      # With no privileges in our empty role, we should blow up

      assert_equal 1, user.roles.count
      assert_equal 0, user.permissions.size

      assert_raises( PermissionFailure, "Should fail with no grants at all" ) { yield }

      # If array of one privilege supplied, treat as single privilege

      if priv_or_privs.size == 1

        # Single privilege supplied; assign it to our role, and
        # check that it works.

        User.as( users(:universal_grant_guy) ) do
          priv = priv_or_privs.first.dup
          priv.role = role
          priv.save!
          user.permissions :force_reload
        end

        assert_nothing_raised { yield }

      else

        # Multiple privileges.  Make sure each individually doesn't
        # grant access...

        privs = priv_or_privs.collect &:dup
        privs.each do |priv|

          User.as( users(:universal_grant_guy) ) do
            priv.role = role
            priv.save!
          end

          user.permissions :force_reload
          assert_raises( PermissionFailure, "Should fail with only priv #{priv}" ) { yield }

          User.as( users(:universal_grant_guy) ) do
            priv.update_attribute :role, roles(:ricardo_twiddler) # displace...
          end

        end

        # ... but that they collectively do:

        User.as( users(:universal_grant_guy) ) do
          privs.each { |priv| priv.update_attribute :role, role }
        end

        user.permissions :force_reload
        assert_nothing_raised { yield }

      end
    end

  end

  # :call-seq:
  #   assert_fails_even_with perm_or_perms { code; code ... } 
  #
  # The opposite of assert_requires; demands that the code
  # throw a PermissionFailure even if the perm_or_perms are
  # all in place.

  def assert_fails_even_with( perm_or_perms )

    with_permission( perm_or_perms ) do

      assert_raises( PermissionFailure ) { yield }

    end
    
  end

  # :call-seq:
  #   with_permission perm_or_perms { code; code ... } 
  #
  # Runs the code in an environment with a user that has only
  # the given permissions...

  def with_permission( perm_or_perms )

    perms = perm_or_perms.is_a?( Permission ) ? [perm_or_perms] : perm_or_perms
    perms = perms.collect &:dup

    with_test_role_for_unprivileged_guy(:no_grants) do |user, role|

      User.as( users( :universal_grant_guy )) do
        perms.each do |perm|
          perm.role = role
          perm.save!
        end
      end

      user.permissions :force_reload
      yield

    end
    
  end

  # :call-seq:
  #   blog_post_permission :perm_attribute => perm_attr_val, ...
  #
  # Quickie line-saver:  generate a Permission to :post to Blog,
  # with extra attributes as supplied in the arguments.

  def blog_post_permission( args = {} )
    Permission.new( args.reverse_merge( :privilege            => :post, 
                                        :class_name           => 'Blog',
                                        :is_grant             => false,
                                        :has_grant_option     => false,
                                        :target_owned_by_self => false
                                        ))
  end

  # Returns a Permission granting 'privilege' on one ojbect, 'obj'

  def one_object_perm privilege, obj
    Permission.new( :privilege    => privilege,
                    :class_name   => obj.class.name,
                    :is_grant     => false,
                    :has_grant_option => false,
                    :target_owned_by_self => false,
                    :target       => obj
                    )
    
  end

  # Returns a Permission granting 'privilege' on any object of class 'klass'
  # owned by 'owner'.

  def owner_perm privilege, klass, owner
    Permission.new( :privilege    => privilege,
                    :class_name   => klass.name,
                    :is_grant     => false,
                    :has_grant_option => false,
                    :target_owned_by_self => false,
                    :target_owner => owner
                    )
    
  end

  # Returns a Permission granting 'privilege' on any object of class 'klass'
  # whose owner_firm is set to 'firm'.

  def owner_firm_perm privilege, klass, firm
    Permission.new( :privilege    => privilege,
                    :class_name   => klass.name,
                    :is_grant     => false,
                    :has_grant_option => false,
                    :target_owned_by_self => false,
                    :target_owner_firm => firm
                    )
    
  end

  # Returns a Permission granting 'privilege' on any object of class 'klass'
  # which is "owned by self".

  def self_owner_perm privilege, klass
    Permission.new( :privilege    => privilege,
                    :class_name   => klass.name,
                    :is_grant     => false,
                    :has_grant_option => false,
                    :target_owned_by_self => true
                    )
  end

  # Returns a Permission granting 'privilege' on any object of class 'klass',
  # at all.

  def wildcard_perm privilege, klass
    Permission.new( :privilege    => privilege,
                    :class_name   => klass.name,
                    :is_grant     => false,
                    :has_grant_option => false,
                    :target_owned_by_self => false
                    )
  end

 end
end
