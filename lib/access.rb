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
      message += ((target.name||"UNNAMED")+' ') if target.respond_to?( :name )
      if target.is_a?( ActiveRecord::Base )
        targ_id = target.id
        if targ_id.nil?
          message += "(UNSAVED)"
        else
          message += "(" + targ_id.to_s + ")"
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

    module ClassMethods

      # Sole argument is an array of strings that name attributes that
      # are possible access keys for this class.  Note, if 'foo' is
      # used by any access-controlled model as an access control key,
      # there *must* be a corresponding column in the class's database
      # table (and not be, e.g., a computed pseudo-attribute), and
      # Permission objects *must* have a 'target_foo' attribute, again
      # with a corresponding column in the 'permissions' table.

      def declare_access_control_keys( *ack_list )
        ack_list = ack_list.collect( &:to_s )
        instance_eval <<-EOF
          def self.access_control_keys; #{ack_list.inspect}; end
        EOF
      end

      def access_control_keys   # :nodoc:
        # Defaults
        if @all_acks.nil?
          @all_acks = []
          @all_acks <<= 'id'
          owner_ack = self.owner_access_control_key
          @all_acks << owner_ack unless (owner_ack.nil? || owner_ack == 'id')
        end
        @all_acks
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
        ack = ack.to_s unless ack.nil?
        instance_eval <<-EOF
          def self.owner_access_control_key; #{ack.inspect}; end
        EOF
      end

      def owner_access_control_key # :nodoc:
        # Default behavior
        @owner_ack ||= column_names.include?('owner_id')? 'owner_id' : nil
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
        find :all, add_priv_check_to_query_args( priv, keyword_args )
      end

      def add_priv_check_to_query_args( privilege, keyword_args  ) # :nodoc:

        keyword_args = keyword_args.clone
        user = keyword_args.delete( :user )
        perm_conds = where_permits( privilege, :user => user ) 

        if keyword_args[:conditions].nil?
          keyword_args[:conditions] = perm_conds
        else
          old_conds = sanitize_sql( keyword_args[:conditions] )
          keyword_args[:conditions] = perm_conds + ' and ' + old_conds
        end

        keyword_args

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
        count add_priv_check_to_query_args( priv, keyword_args )
      end

      # :call-seq:
      #   Klass.where_permits :operation[, :user => ... ]
      # 
      # Returns the text of a SQL condition (suitable for use in a
      # where clause) which selects records of this class's table
      # on which the user (default: User.current) is permitted to
      # perform operation :operation.

      def where_permits( priv, keyword_args = {} )

        if priv == :forbidden_operation
          # ... lest wildcards "allow" it ...
          return '2 + 2 = 5'
        end

        # Note that we use Rails' pseudo-bind-parameters below
        # to avoid DB dependencies on the syntax for "false"

        user = keyword_args[:user] || User.current

        if user.nil?
          raise ArgumentError.new("Cannot generate where clause without user")
        end

        keys = { 
          :user       => user,
          :privilege  => priv.to_s,
          :class_name => self.name,
          :false      => false,
        }

        table           = self.table_name
        owner_id_attr   = self.owner_access_control_key
        self_owner_cond = owner_id_attr.nil? ? '2 + 2 = 5' : 
                          "#{table}.#{owner_id_attr} = :user"

        return sanitize_sql( [ <<-END_SQL, keys ] )
          exists
            (select 'x' from permissions p
             where exists (select 'x' from role_assignments
                           where user_id = :user
                             and role_assignments.role_id = p.role_id
                             and #{RoleAssignment.current_sql_condition})
               and (p.privilege  = :privilege or p.privilege = 'any')
               and (p.class_name = :class_name)
               and (p.is_grant   = :false)
               and (p.target_owned_by_self = :false or #{self_owner_cond})
               and #{self.permission_grant_conditions}
            )
        END_SQL

      end

      def permits_for_id?( priv, id ) # :nodoc:

        sql = 
          sanitize_sql(["select 'x' from #{table_name} where id = ? and ",id])+
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

      include Access::RequirePrivilege::ClassMethods
      
    end

    # The usual hook for ClassMethods...

    def self.included( klass )  # :nodoc:
      klass.extend ClassMethods

      # Any reason to *ever* allow this?

      klass.never_permit_anyone :to_update_attribute => :id
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
                                     :target    => associate )
      else
        log_hash[:success] = true
        Smartguard::Logging.log( log_hash )
        logger.warn "=== #{log_text}"
      end
      self
    end

    private

    def check_user_set!(user, priv, associate)
      if user.nil?
        raise PermissionFailure.new("Not authorized to #{priv} because " +
                                    "current user is not set", 
                                    :privilege => priv, :target => associate)
      end
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
