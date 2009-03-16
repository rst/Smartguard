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

module SmartguardBasicUser

  def self.included( klass )
    klass.extend ClassMethods
    klass.has_many :role_assignments
    klass.cattr_accessor :current, :of_record
  end

  module ClassMethods

    # Weird metaprogramming trick to set up the roles association,
    # even though the current sql condition isn't known until after
    # we've connected to the database...

    def ensure_roles_assoc      # :nodoc:
      return if @have_roles_assoc
      undef_method :roles
      self.has_many :roles, 
        #:through => :role_assignments,
        :finder_sql => 'select * from roles where id in ' +
                        role_assigned_cond('#{id}'),
        :counter_sql => 'select count(*) from roles where id in ' +
                        role_assigned_cond('#{id}')
      @have_roles_assoc = :true
    end

    def role_assigned_cond( id_stub ) #:nodoc:
      return <<-END_SQL
        (select id from roles
         start with id in (select role_id from role_assignments
                           where user_id = #{id_stub}
                           and #{RoleAssignment.current_sql_condition})
               connect by prior parent_role_id = id)
      END_SQL
    end

    # :call-seq:
    #   User.as( some_user[, :acting_as => other_user]) do ... end
    #
    # Runs the body with User.of_record set to some_user,
    # and User.current set to other_user.  If the :acting_as
    # keyword argument is omitted, both User.current and
    # User.acting_as are set to some_user.

    def as( user, options = {} )

      raise ArgumentError, "incorrect keyword to User.as" if
        options.size > 1 || (options.size == 1 && 
                             options.keys.first != :acting_as)

      old_current   = User.current
      old_of_record = User.of_record
      
      User.of_record = user
      User.current   = options[:acting_as] || user

      yield

    ensure

      User.current   = old_current
      User.of_record = old_of_record
      
    end

    # :call-seq:
    #   User.acting_as_user_of_record do ... end
    #
    # Runs the body with User.current temporarily set to the 
    # user of record.  Useful for managing settings related to
    # authorization (as opposed to permissioning), e.g., the
    # "change my password" action in the password controller,
    # which should *always* change the password of the *current*
    # user, never mind who they're aliased to.

    def acting_as_user_of_record
      old_current  = User.current
      User.current = User.of_record
      yield
    ensure
      User.current = old_current
    end

    # An 'owned by self' permission on User is permission to manipulate
    # your own password, preferences, or whatever.  So...

    def owner_access_control_key # :nodoc:
      'id'
    end

  end

  # All permissions of this user, as an array.
  # This isn't actually an association proxy, but calling it
  # with a non-nil first argument will force cached data to
  # be reloaded anyway.

  def permissions( force_reload = false )

    # Two levels of joins here, so can't use has_many :through

    @permissions = nil if force_reload

    cond_str = 'role_id in ' + self.class.role_assigned_cond( '?' )
    @permissions ||= Permission.find :all, :conditions => [cond_str, self]

    @permissions_by_class_and_op = sort_permissions( @permissions )

    return @permissions

  end

  # Weird metaprogramming trick; we want the effect of has_many :roles,
  # but with conditions including RoleAssignment.current_sql_condition,
  # which varies with the database.  So we use this trick to bind
  # the association late...

  def roles( force_reload = false ) # :nodoc:
   self.class.ensure_roles_assoc # redefines the 'roles' method...
   self.roles( force_reload )    # ... now invoke the new one.
  end

  # Only the grant permissions of this user, as an array.

  def grant_permissions( force_reload = false )
    permissions( force_reload ).select( &:is_grant? )
  end

  # Returns true iff this user has privilege 'privilege' on
  # object 'obj'

  def can?( privilege, obj )

    return false if privilege == :forbidden_operation # lest wildcards allow it

    class_name  = obj.class.sg_base_class_name
    class_perms = perms_sorted[class_name] || {}

    (class_perms[privilege] || []).each do |perm|
      return true if perm.allows_internal?( obj, self )
    end

    (class_perms[:any] || []).each do |perm|
      return true if perm.allows_internal?( obj, self )
    end

    return false

  end

  # Returns all permissions for privilege 'privilege' on class 'klass',
  # including direct permissions and applicable wildcards, but excluding
  # grants.

  def all_permissions( privilege, klass )

    class_perms = self.perms_sorted[ klass.name ] || {}
    all_perms = class_perms[ privilege ] || []

    if !class_perms[ :any ].nil?
      all_perms = all_perms + class_perms[ :any ]
    end

    return all_perms

  end

  # Returns true iff this user has a permission which grants
  # 'operation' on some set of objects of class 'klass' (which may be
  # passed in as a class object, or as a string naming a class).  This
  # method just checks the permission structure; it does not guarantee
  # that any such object currently exists.  For that, try
  #
  #       klass.count_permitting( operation, :user => user ) > 0
  #
  # which tells you if the user could perform the operation on some
  # object *right now*.

  def could_ever?( operation, klass )
    klass = klass.name if klass.is_a?( Class )
    klass_perms = perms_sorted[klass]
    return !klass_perms.nil? &&
      (!klass_perms[operation].nil? || !klass_perms[:any].nil?)
  end

  protected

  def perms_sorted( force_reload = false ) # :nodoc:
    permissions( force_reload )
    @permissions_by_class_and_op
  end

  def sort_permissions( perms )

    perms_sorted = {}

    perms.each do |perm|
      if !perm.is_grant
        perms_sorted[perm.class_name] ||= {}
        perms_sorted[perm.class_name][perm.privilege] ||= []
        perms_sorted[perm.class_name][perm.privilege] << perm
      end
    end

    perms_sorted

  end

end
