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

# An extended SecurityError for permission failures.
# 
# Has three extra attributes:
#
#  privilege    --- the privilege that was not granted
#  target       --- the object on which it was not granted
#  target_class --- the class of the object.  (We may drop this;
#                   it's always currently redundant).

class PermissionFailure < SecurityError

  attr_accessor :privilege, :target, :target_class

  def initialize( message, keys = {} )
    target = keys[:target]
    unless keys[:target].nil?
      message += " " + target.class.to_s.underscore + " "

      has_name = target.respond_to?( :name )
      
      if has_name

        name = begin 
                 target.name 
               rescue ActiveRecord::MissingAttributeError
                 'UNNAMED'
               end
                 
        message += (name || 'UNNAMED') + ' '

      end

      if target.is_a?( ActiveRecord::Base )
        if target.new_record?
          message += "(UNSAVED)"
        else
          message += "(" + target.id.to_s + ")"
        end
      end
    end
    super( message )
    self.privilege    = keys[:privilege]
    self.target       = keys[:target]
    self.target_class = keys[:target_class] || self.target.class
  end

end

module Access

  module Controlled

    # The usual hook for ClassMethods...

    def self.included( klass )  # :nodoc:

      klass.extend ClassMethods

      # Set up inheritable attributes for basic privilege checks.

      klass.class_inheritable_accessor :sg_access_control_keys,
        :instance_writer => false
      klass.class_inheritable_accessor :sg_owner_access_control_key,
        :instance_writer => false

      # Set up inheritable attributes for require_privilege, etc.
      
      klass.class_inheritable_reader :declared_privileges
      klass.class_inheritable_accessor :attribute_block_set_groups,
        :instance_writer => false
      klass.class_inheritable_accessor :sg_reflected_privileges
      klass.class_inheritable_reader :sg_deferred_permission_wrappers

      klass.class_inheritable_accessor :sg_implied_priv_to_privs, :instance_writer => false
      klass.class_inheritable_accessor :sg_priv_to_implied_privs, :instance_writer => false
      klass.sg_implied_priv_to_privs = Hash.new { |h,k| h[k] = Array.new }
      klass.sg_priv_to_implied_privs = Hash.new { |h,k| h[k] = Array.new }

      klass.extend Access::RequirePrivilege::ClassMethods

      # And set up defaults for some of these, in base classes only.
      # (Don't re-set-up defaults if they're being inherited!)

      if klass.declared_privileges.nil?

        klass.write_inheritable_array :declared_privileges,
          Access::RequirePrivilege::DEFAULT_DECLARED_PRIVILEGES 
        klass.attribute_block_set_groups = [['owner', 'owner_id']]
        klass.write_inheritable_attribute( :sg_reflected_privileges, {} )

        # Any reason to *ever* allow this?

        klass.never_permit_anyone :to_update_attribute => :id

      end

    end

    module ClassMethods

      def class_inheritable_accessor( sym, opts = {} )
        class_attribute sym, opts
      end

      def class_inheritable_reader( sym )
        class_attribute sym, :instance_writer => false
      end

      def write_inheritable_attribute( sym, val )
        self.send( (sym.to_s + '='), val )
      end

      def read_inheritable_attribute( sym )
        self.send( sym )
      end

      def write_inheritable_array(key, elements)
        write_inheritable_attribute(key, []) if read_inheritable_attribute(key).nil?
        write_inheritable_attribute(key, read_inheritable_attribute(key) + elements)
      end

      def write_inheritable_hash(key, hash)
        write_inheritable_attribute(key, {}) if read_inheritable_attribute(key).nil?
        write_inheritable_attribute(key, read_inheritable_attribute(key).merge(hash))
      end

      # Sole argument is an array of strings that name attributes that
      # are possible access keys for this class.  Note, if 'foo' is
      # used by any access-controlled model as an access control key,
      # there *must* be a corresponding column in the class's database
      # table (and not be, e.g., a computed pseudo-attribute), and
      # Permission objects *must* have a 'target_foo' attribute, again
      # with a corresponding column in the 'permissions' table.

      def declare_access_control_keys( *ack_list )
        self.sg_access_control_keys = ack_list
      end

      def access_control_keys   # :nodoc:

        acks = self.sg_access_control_keys
        return acks unless self.sg_access_control_keys.nil?

        # Not explicitly set.  Implement default behavior...

        all_acks = []
        all_acks <<= 'id'
        owner_ack = self.owner_access_control_key
        all_acks << owner_ack unless (owner_ack.nil? || owner_ack == 'id')
        self.sg_access_control_keys = all_acks

        return all_acks

      end

      # Argument is a string naming the access key attribute 
      # that contains the id of the owner in the users table,
      # or nil, to indicate that there is no owner access control
      # key.
      #
      # Settable for the sake of the User class itself, which
      # uses 'id' as the owner_access_key, so owned_by_self
      # permissions can be used to grant users selective
      # rights on their passwords, prefs, etc.

      def declare_owner_access_control_key( ack )
        self.sg_owner_access_control_key = ack
      end

      def owner_access_control_key # :nodoc:

        ack = self.sg_owner_access_control_key
        return ack unless ack.nil?

        # Default behavior
        self.sg_owner_access_control_key = 
          column_names.include?('owner_id')? 'owner_id' : nil

        return self.sg_owner_access_control_key

      end

      # Declare that one privilege implies another.  Example:
      #   declare_implied_privilege :assign, :implies => :find
      # Means that a user who is granted assign privilege is automatically
      # granted an equivalent find privilege (with the same access control
      # settings, etc).
      def declare_implied_privilege(priv, opts)
	raise ArgumentError.new("options must include the name of the implied privilege") unless opts.include?(:implies)
	implied_priv = opts[:implies]
	self.sg_implied_priv_to_privs[implied_priv] << priv   # example sg_implied_priv_to_privs[:find] => [:assign]
	self.sg_priv_to_implied_privs[priv] << implied_priv   # example sg_priv_to_implied_privs[:assign] => [:find]
      end

      # :call-seq:
      #   Klass.all_permitting :privilege[, :user => ..., :find_arg => ...]
      #
      # Finds all records of the given class on which the
      # :user (default: User.current) has privilege :privilege. 
      #
      # For more complex finds (involving, e.g., additional conditions),
      # consider the use of where_permits (q.v.), along the lines of
      #
      #   Klass.find :all,
      #              :conditions => Klass.where_permits(...),
      #              :other_opt  => ...
      #
      # Keyword args other than :user (:include, etc.) are as for find :all.
      # A :conditions keyword argument may be supplied, in which case, they
      # are conjoined with the permission check.  So, for instance
      #
      #   Klass.all_permitting :edit, :conditions => "name like '%fred%'"
      #
      # is equivalent to
      #
      #   Klass.find :all,
      #              :conditions => "name like '%fred%' and " + 
      #                             Klass.where_permits( :edit )

      def all_permitting( priv, keyword_args = {} )
        perm_conds = where_permits( priv, :user => keyword_args.delete(:user) ) 
        self.applying_deprecated_query_args( keyword_args ).where( perm_conds )
      end

      # Apply some of the deprecated query args --- the ones that we are
      # actually known to use.

      def applying_deprecated_query_args( args ) # :nodoc:
        rel = self.all
        rel = rel.includes(args[:include]) if args[:include]
        rel = rel.where(args[:conditions]) if args[:conditions]
        rel = rel.order(args[:order])      if args[:order]
        rel = rel.limit(args[:limit])      if args[:limit]
        rel
      end

      # :call-seq:
      #   Klass.count_permitting :privilege[, :user => ..., :count_arg => ... ]
      #
      # Returns the number of records of the given class on which 
      # the given user (default: User.current) has the given privilege.
      # Other keyword arguments as for ordinary class-level 'count'.
      #
      # Keyword arguments other than :user are passed through to 'count'.
      # Any :conditions supplied are conjoined to the permissions check,
      # so, for instance, 
      #
      #   Klass.count_permitting :edit, :conditions => "name like '%fred%'"
      #
      # is equivalent to
      #
      #   Klass.count :all,
      #               :conditions => "name like '%fred%' and " + 
      #                              Klass.where_permits( :edit )

      def count_permitting( priv, keyword_args = {} )
        all_permitting( priv, keyword_args ).count
      end

      # :call-seq:
      #   Klass.where_permits :operation[, :user => ... ]
      # 
      # Returns the text of a SQL condition (suitable for use in a
      # where clause) which selects records of this class's table
      # on which the user (default: User.current) is permitted to
      # perform operation :operation.

      def where_permits( priv, keyword_args = {} )
        priv, association = disassemble_priv( priv )
        if association.nil?
          return <<-END_SQL
            (#{table_name}.id in
             #{self.ids_permitting_internal( priv, keyword_args )})
          END_SQL
        else
          klass = self.class_for_associate(association)
          fk = self.reflect_on_association(association).foreign_key.to_s
          return <<-END_SQL
            (#{table_name}.#{fk} in
             #{klass.ids_permitting_internal( priv, keyword_args )})
          END_SQL
        end
      end

      # :call-seq:
      #   Klass.ids_permitting :operation[, :user => ... ]
      # 
      # Returns the text of a SQL subquery (surrounded by parens
      # to avoid "macro leakage") which returns ids of all rows
      # on which the user (default: User.current) is permitted to
      # perform operation :operation

      def ids_permitting( priv, keyword_args = {} )
        priv, association = disassemble_priv( priv )
        if association.nil?
          return self.ids_permitting_internal( priv, keyword_args.merge( :distinct => true ))
        else
          klass = self.class_for_associate(association)
          fk = self.reflect_on_association(association).foreign_key.to_s
          return <<-END_SQL
            (select id from #{table_name} where #{table_name}.#{fk} in
             #{klass.ids_permitting_internal( priv, keyword_args )})
          END_SQL
        end
      end

      def ids_permitting_internal( priv, keyword_args = {} ) # :nodoc:

        if priv == :forbidden_operation
          # ... lest wildcards "allow" it ...
          return "(select #{table_name}.id from #{table_name} where 2+2=5)"
        end

        user = keyword_args[:user] || User.current
        klass_perms = (user.perms_for_class( sg_base_class_name ) || {})
        perms = klass_perms[priv] || []
        perms += klass_perms[:any] || []

        if perms.empty?
          return "(select #{table_name}.id from #{table_name} where 2+2=5)"
        end

        clauses = perms.collect{ |perm|
          # nasty special case here for perms that have *both* target_user_id
          # set and target_owned_by_self
          owner_ack = self.owner_access_control_key
          if (self.access_control_keys.include?(owner_ack) and
              perm.target_owner_id != nil and
              perm.target_owned_by_self and
              perm.target_owner_id != nil and
              perm.target_owner_id != user.id)
            return nil
          else
            subclauses = self.access_control_keys.collect{ |k|
              target_id = perm['target_' + k]
              if (k == owner_ack && perm.target_owned_by_self)
                target_id ||= user.id
              end
              if target_id.nil?
                nil
              else
                sanitize_sql ["#{table_name}.#{k} = ?", target_id]
              end
            }.compact
            if !perm.target_id.nil?
              subclauses << sanitize_sql(["#{table_name}.id = ?", perm.target_id])
            end
            if subclauses.empty?
              "(1 = 1)"
            else
              "(" + subclauses.join(' and ') + ")"
            end
          end
        }
        clauses = clauses.compact
        where_clause =
          if clauses.empty?
            '(1 = 1)'
          else
            clauses.join(' or ')
          end

        maybe_distinct = keyword_args[:distinct] ? 'distinct' : ''

        retval = <<-END_SQL
          (select #{maybe_distinct} #{table_name}.id from #{table_name}
           where #{where_clause})
        END_SQL

        return retval

      end

      def disassemble_priv( priv ) # :nodoc:
        if priv.is_a?( Array )
          association = priv.last
          priv = priv.first
          return priv, association
        else
          return priv, nil
        end
      end

      # Returns all users with privilege 'priv' on 'obj'

      def users_permitted_to( priv, obj )
        User.where("id in (#{users_permitted_sql( priv, obj )})").to_a
      end

      # Returns SQL for a select which returns the IDs of all users
      # which have privilege 'priv' on 'obj', as a string,
      # "select id from users where...", which is suitable for use
      # as a subquery, that is...
      #
      #   "where users.id in (#{MinMaxList.users_permitted_sql(:update, obj)})"

      def users_permitted_sql( priv, obj )

        (privilege, associate) = obj.send( :disassemble_priv, priv )
        return 'select id from users where 1 = 2' if associate.nil?

        table = associate.class.table_name

        # look up privs that imply this one
	implied_privs_conds = self.sg_implied_priv_to_privs[priv].collect { |x| "or p.privilege = '#{x}'" }.join(" ")

        keys = { 
          :true       => true,
          :false      => false,
          :privilege  => privilege.to_s,
          :class_name => associate.class.sg_base_class_name
        }

        recursive = Smartguard::DbSpecific.recursive

        non_owner_query = sanitize_sql( [ <<-END_SQL, keys ] )
         select user_id from role_assignments
         where (#{RoleAssignment.current_sql_condition})
           and role_assignments.role_id in
             (with #{recursive} all_role_ids(id) as
              ((select p.role_id
                from permissions p, #{table}
                where (p.privilege  = :privilege or p.privilege = 'any' #{implied_privs_conds})
                  and (p.class_name = :class_name)
                  and (p.is_grant   = :false)
                  and (#{table}.id  = #{associate.id})
                  and (p.target_owned_by_self = :false)
                  and #{associate.class.permission_grant_conditions})
                union all
                (select roles.id 
                 from roles inner join all_role_ids
                   on roles.parent_role_id = all_role_ids.id))
              select id from all_role_ids)
        END_SQL

        owner_id_attr = associate.class.owner_access_control_key

        if owner_id_attr.nil?
          return non_owner_query
        else
          return sanitize_sql( [ <<-END_SQL, keys ] )
           with #{recursive}
             granting_assigns_nonrecursive(role_id, user_id) as 
               (select p.role_id, #{table}.#{owner_id_attr} as user_id
                from permissions p, #{table}
                where #{table}.id = #{associate.id}
                  and (p.privilege  = :privilege or p.privilege = 'any' #{implied_privs_conds})
                  and (p.class_name = :class_name)
                  and (p.is_grant   = :false)
                  and (#{table}.id  = #{associate.id})
                  and (p.target_owned_by_self = :true)
                  and #{associate.class.permission_grant_conditions}),
             granting_assigns(role_id, user_id) as
               ((select role_id, user_id from granting_assigns_nonrecursive)
                union all
                (select roles.id as role_id, granting_assigns.user_id
                 from roles inner join granting_assigns
                   on roles.parent_role_id = granting_assigns.role_id))
             (select granting_assigns.user_id
              from granting_assigns inner join role_assignments
                on granting_assigns.user_id = role_assignments.user_id
                   and granting_assigns.role_id = role_assignments.role_id
              where #{RoleAssignment.current_sql_condition})
             union
             (#{non_owner_query})
          END_SQL
        end

      end

      def check_user_set!(user, priv, associate) # :nodoc:
        if user.nil?
          raise PermissionFailure.new("Not authorized to #{priv} because " +
                                      "current user is not set", 
                                      :privilege => priv, :target => associate)
        end
      end

      def permits_for_id?( priv, id ) # :nodoc:

        sql = 
          sanitize_sql(["select id from #{table_name} where id = ? and ",id])+
                       where_permits( priv )

        flag = connection.select_values( sql )
            
        return flag != []
        
      end

      def permission_grant_conditions # :nodoc:
        table = self.table_name
        @perm_grant_conditions ||= self.access_control_keys.collect do |attr|
          "(p.target_#{attr} is null or #{table}.#{attr} = p.target_#{attr})"
        end.join(' and ')
      end

      # Given a grant permission, return names and ids of individual objects
      # of this class which could be permitted by the grant.  These are
      # sensible values for target_id in a new permission coined off the
      # grant, in a format which is meant to be useful for Rails 'select'
      # form helpers.
      #
      # Assumes the class has a 'name' column; for more general solutions,
      # see choice_hashes_for_grant, which this trivially wraps.

      def choices_for_grant_target( grant_perm )
        choices = choice_hashes_for_grant_target( grant_perm, :columns=>'name')
        return choices.collect{ |h| [ h['name'], h['id'] ] }
      end

      # Similar to choices_for_grant_target (q.v.), but instead returns
      # an array of hashes whose keys include 'id', and whatever else 
      # is requested via the :columns keyword parameters.  
      #
      # Note that keys in the hashes are strings, not symbols.
      #
      # Takes two optional keyword arguments ---
      #   :columns --- a string containing raw SQL to specify columns
      #                other than :id that will be in the returned hashes,
      #   :joins --- joins to the class's table from which :columns may
      #              be taken
      #
      # Note that this works internally by calling connection.select_all.
      # ID's are correctly cast, but if using pg, other columns may be
      # left as strings.

      def choice_hashes_for_grant_target( grant_perm, options = {} )

        options.assert_valid_keys( :columns, :joins )
        cols = options[:columns]
        cols = ', ' + cols unless cols.nil?

        tbl = self.table_name
        sql = <<-END_SQL
          select distinct #{tbl}.id #{cols}
          from permissions p, #{tbl} #{options[:joins]}
          where p.id = :grant
            and p.class_name in ('any', :klass)
            and p.is_grant = :true
            and p.target_owned_by_self = :false
            and #{self.permission_grant_conditions}
        END_SQL

        query = sanitize_sql [sql, 
                              { :grant => grant_perm,
                                :klass => self.name,
                                :true  => true,
                                :false => false
                              }]
        connection.select_all( query ).tap do |recs|
          recs.each do |rec|
            rec["id"] = rec["id"].to_i
          end
        end

      end

      # The standard 'exists?' implementation instantiates an
      # object with *only* the id populated, and not any of the
      # access control keys.  Strangely, this leads to permission
      # failures.  The easiest way to work around this sticking
      # only to documented API, albeit with nasty overhead:

      def exists?( arg )
        begin
          super( arg )
        rescue PermissionFailure
          return true;
        end
      end

      # Memoized versions of base_class and base_class.name

      def sg_base_class_name    # :nodoc:
        @sg_base_class_name ||= self.base_class.name
      end

      def sg_base_class         # :nodoc:
        @sg_base_class ||= self.base_class
      end
      
    end

    include Access::RequirePrivilege::InstanceMethods

    public

    # Returns true if the user has privilege 'priv' on this object.
    #
    # First argument may also be a pair, [:privilege, :associate],
    # to check privilege on an associated object.

    def permits?( priv, user = User.current )
      (priv, associate) = disassemble_priv( priv )
      check_user_set!(user, priv, associate)
      user.can?( priv, associate )
    end

    # Returns all users with privilege 'priv' on this object

    def users_permitted_to( priv )
      sql = self.class.users_permitted_sql( priv, self )
      User.where("id in (#{sql})")
    end

    # Returns SQL for a select which returns the IDs of all users
    # which have privilege 'priv' on 'obj', as a string,
    # "select id from users where...", which is suitable for use
    # as a subquery, that is...
    #
    #   "where users.id in (#{my_list.users_permitted_sql(:update)})"

    def users_permitted_sql( priv )
      self.class.users_permitted_sql( priv, self )
    end

    # Throws a PermissionFailure exception if the user
    # does *not* have privilege 'priv' on this object.
    # Otherwise, returns the object itself, to allow for
    # use as an annotation, e.g.
    #
    #    acct = Account.find( some_id ).check_permission!( :queue_trades )
    #
    # First argument may also be a pair of 
    # [:privilege, :associate_name] to check privilege
    # on an associated object...

    def check_permission!( priv, user = User.current )

      (priv, associate) = disassemble_priv( priv )

      if associate.nil?
        log_text = "permission check: #{priv} on MISSING associate"
        logger.warn "=== FAILED #{log_text}"
        raise PermissionFailure.new( "not authorized to #{priv}",
                                     :privilege => priv,
                                     :target => self )
      end

      associate_name = associate.class.to_s + ' ' +
        ((associate.has_attribute?(:name)? associate.name : nil) || 'X')
      log_text = "permission check: #{priv} #{associate_name}(#{associate.id})"

      check_user_set!(user, priv, associate)

      log_hash = { 
        :model_class => associate.class.name,
        :model_id    => associate.id,
        :privilege   => priv.to_s,
        :user_id     => user.id,
        :user_name   => user.name
      }

      if !user.can?( priv, associate )
        logger.warn "=== FAILED #{log_text}"
        log_hash[:success] = false
        Smartguard::Logging.log( log_hash )
        raise PermissionFailure.new( "not authorized to #{priv}",
                                     :privilege => priv,
                                     :target    => self )
      else
        log_hash[:success] = true
        Smartguard::Logging.log( log_hash )
        logger.debug "=== #{log_text}"
      end
      self
    end

    private

    def check_user_set!(user, priv, associate)
      self.class.check_user_set!(user, priv, associate)
    end

    def disassemble_priv( priv )  # :nodoc:
      associate = self
      if priv.is_a?( Array )
        associate = self.send priv.last
        priv = priv.first
      end
      return priv, associate
    end

  end
end
