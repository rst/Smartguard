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
        :finder_sql => Proc.new {
          sanitize_sql ['select * from roles where id in ' +
                          self.class.role_assigned_cond(':id'),
                        {:id => id}]
        },
        :counter_sql => Proc.new {
          sanitize_sql ['select count(*) from roles where id in ' +
                          self.class.role_assigned_cond(':id'),
                        {:id => id}]
        }

      # Apparently, 'undef_method' doesn't just undefine the method,
      # it puts in a "no such method here" stub that hides the method
      # that 'has_many' defines on our GeneratedFeatureMethods module.
      # So, we have to explicitly forward it here.  Gaaaaaah!

      meth = generated_feature_methods.instance_method( :roles )
      define_method :roles do | *args |
        meth.bind( self ).call( *args )
      end

      @have_roles_assoc = :true
    end

    def role_assigned_cond( id_stub ) #:nodoc:

      # See also roles_without_assigned_role, below, which
      # knows what it does, and does something similar in-core.
      # Tested only indirectly via tests on could_without_role?

      return <<-END_SQL
        (with recursive all_role_ids(id, parent_id) as
          ((select roles.id, roles.parent_role_id
            from role_assignments inner join roles
              on roles.id = role_assignments.role_id
            where role_assignments.user_id = #{id_stub}
            and #{RoleAssignment.current_sql_condition})
           union all
           (select roles.id, roles.parent_role_id
            from roles inner join all_role_ids
              on roles.id = all_role_ids.parent_id))
         select id from all_role_ids)
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
  # NOTE:  This only returns permissions stored explicitly in the database:
  # implied permissions are added on the fly (see perms_for_class()).
  # This isn't actually an association proxy, but calling it
  # with a non-nil first argument will force cached data to
  # be reloaded anyway.

  def permissions( force_reload = false )

    # Two levels of joins here, so can't use has_many :through
    if force_reload
      @permissions = nil 
      @permissions_by_class_and_op = {}
    end

    cond_str = 'role_id in ' + self.class.role_assigned_cond( '?' )
    if !@permissions
      @permissions ||= Permission.find :all, :conditions => [cond_str, self]
    end

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

  # Returns all roles we'd have if the given role *wasn't* assigned;
  # useful in rare cases where we want to know what would happen if
  # we removed it.  See 'could_without_role?' below, q.v.

  def roles_without_assigned_role( target_role ) # :nodoc:

    other_roles = []

    collect_role = lambda do |role|
      unless role.nil? || other_roles.include?( role )
        other_roles << role
        collect_role.call( role.parent_role )
      end
    end

    self.role_assignments.select(&:current?).each do |ra|
      base_role = ra.role
      collect_role.call( base_role ) unless base_role == target_role
    end

    return other_roles

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
    class_perms = perms_for_class(class_name) || {}

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

    class_perms = self.perms_for_class( klass.name ) || {}
    all_perms = class_perms[ privilege ] || []

    if !class_perms[ :any ].nil?
      all_perms = all_perms + class_perms[ :any ]
    end

    return all_perms

  end

  # Permission check hack...
  #
  # Check to see if a user could perform a given operation,
  # even without a particular role.
  #
  # The sole use case for this extraordinarily weird check
  # is checking "delete role" in user administration.  In
  # particular, we want to keep users from deassigning their
  # own "user admin" roles.  (If they do, even by mistake, 
  # they no longer have privilege to see the admin page --- 
  # which leaves them staring at an error screen, powerless
  # to correct the damage.)
  #
  # So, before allowing User.current to delete its own role r, we see if
  #
  #    User.current.could_without_role?( :administer, User.current, r )
  #
  # If not, they cannot delete the role --- at least not
  # acting as themselves.

  def could_without_role?( target_role, privilege, obj )

    other_roles = roles_without_assigned_role( target_role )

    perms = self.all_permissions( privilege, obj.class )
    other_perms = perms.select{ |perm| other_roles.include?( perm.role )}
    return other_perms.any?{ |perm| perm.allows?( obj, privilege, self ) }

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
    klass_perms = perms_for_class(klass)
    return !klass_perms.nil? &&
      (!klass_perms[operation].nil? || !klass_perms[:any].nil?)
  end

  protected

  # Add a permission for each implied privilege; e.g. if there is an assign
  # privilege and assign implies find, then automatically create a find
  # permission with the same arguments as the original one.
  # Note:  There was a previous bug where implied permissions were not being
  # created because the class definition had not yet been loaded at the time
  # that the memoized permissions hash was created.  If implied perms are ever
  # mysteriously missing, check for that.
  def implied_perms_for(permissions)
    implied_permissions = []
    permissions.each do |p|
      next if p.class_name.to_sym == :any
      next unless p.target_class_exists?
      p.target_class.sg_priv_to_implied_privs[p.privilege].each do |pi|
	p_new = p.dup
	p_new.privilege = pi
	implied_permissions << p_new
	end
    end
    implied_permissions 
  end

  def perms_for_class( class_name, force_reload = false ) # :nodoc:
    @permissions_by_class_and_op ||= {}
    @permissions_by_class_and_op[class_name] = nil if force_reload 
    if !@permissions_by_class_and_op[class_name]
      permissions = self.permissions(force_reload).select { |p| p.class_name == class_name }
      permissions += implied_perms_for(permissions)
      @permissions_by_class_and_op[class_name] = sort_permissions(permissions)[class_name]
    end
    @permissions_by_class_and_op[class_name]
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
