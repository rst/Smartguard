#--
# Copyright (c) 2007, 2008 Robert S. Thau, Smartleaf, Inc.
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
module SmartguardBasicPermission

  module ClassMethods

    def target_access_control_keys # :nodoc:
      column_names.grep( /^target_/ ) - [ 'target_owned_by_self' ]
    end

    def verify_grant( perm, op )
      log_hash = {
        :model_class => 'Permission',
        :privilege   => 'grant',
        :user_id     => User.current.id,
        :user_name   => User.current.name
      }
      if perm.permits_action?( op, User.current )
        log_hash[:success] = true
        Smartguard::Logging.log( log_hash )
      else
        log_hash[:success] = false
        Smartguard::Logging.log( log_hash )
        raise PermissionFailure.new( "no grant allowing #{op} of",
                                     :privilege => :grant,
                                     :target    => perm )
      end
    end

  end

  def self.included(klass)

    klass.extend ClassMethods

    klass.belongs_to :role
    klass.belongs_to :target_owner, :class_name => 'User', 
      :foreign_key => :target_owner_id

    klass.validates_presence_of :role
    klass.validates_inclusion_of :is_grant,             :in => [true, false]
    klass.validates_inclusion_of :has_grant_option,     :in => [true, false]
    klass.validates_inclusion_of :target_owned_by_self, :in => [true, false]

    # Before any save, check that the current user has an applicable grant.

    klass.before_create do |perm|
      klass.verify_grant( perm, :create )
    end

    klass.before_update do |perm|
      klass.verify_grant( perm, :update )
    end

    klass.before_destroy do |perm|
      klass.verify_grant( perm, :destroy )
    end

  end

  # Different classes support different privileges,
  # so we validate the relevant attributes together:

  def privilege
    attr_val = (read_attribute 'privilege')
    @privilege ||= attr_val.blank? ? nil : attr_val.to_sym
  end

  def privilege=( val )
    @privilege = val.nil? ? val : val.to_sym
    write_attribute 'privilege', val.to_s
  end
  
  def validate

    class_name_ok = false

    begin
      class_name_ok = (class_name.constantize.is_a? Class) if !class_name.nil?
    rescue NameError
      class_name_ok = false
    end

    if !class_name_ok
      errors.add :class_name, "is not the name of an access-controlled class"
    end

    if class_name_ok 
      klass = class_name.constantize
      if !klass.respond_to?( :declared_privileges )
        errors.add :class_name, "is not the name of an access-controlled class"
      elsif klass != klass.base_class
        errors.add :class_name, 
          "has STI base #{klass.base_class}; permissions must attach to that"
      else
        privileges = class_name.constantize.declared_privileges
        if !privileges.include?( privilege ) && privilege != :any
          errors.add :privilege, "is not a permission on #{class_name}"
        end
      end
    end

  end

  # Pseudo-attribute:  the class on which this permission grants privileges.
  # Returns the class object, not the name (that is, Blog, not 'Blog').
  #
  # (This is a settable facade attribute; setting it to
  # a class object, viz: "perm.target = Blog", sets the
  # class_name attribute as well).

  def target_class

    if class_name.nil?; return nil; end

    klass = class_name.constantize
    if klass.nil? || !klass.is_a?( Class )
      raise NameError, "#{class_name} is not the name of a class"
    end

    return klass

  end

  def target_class=( klass )
    self.class_name = klass.nil? ? nil : klass.name
  end

  def target_class_exists?
    klass = self.class_name.split("::").inject(Object) {|m,x|  m.const_defined?(x) ? m.const_get(x) : break;}
    klass != nil
  end

  # Pseudo-attribute for granting privileges on particular objects.

  def target
    if target_id.nil?
      return nil
    end
    return target_class.find( target_id )
  end

  def target=( obj )

    if obj.nil?
      self.target_id = nil
      self.target_name = nil
      return
    end

    unless obj.is_a?( self.target_class )
      raise ArgumentError, "#{obj.class.name} was not a #{self.class_name}"
    end

    self.target_id   = obj.id
    self.target_name = obj.respond_to?( :name ) ? obj.name : nil

  end

  # Privileges (if any) that this permission allows a user to grant.

  def grantable_privileges
    return [] if !self.is_grant?
    return [self.privilege] if self.class_name == 'any'
    klass = self.target_class
    return klass.declared_privileges + [:any] if self.privilege == :any
    return [self.privilege] + klass.sg_priv_to_implied_privs[self.privilege]
  end

  # Because this can be confusing here the expected behavior
  # grant(any_class, any_priv)      - return all declared privs of klass 
  # grant(any_class, named_priv)    - return named_priv + anything it implies
  # grant(named_class, any_priv)    - if named_class==klass return all declared privs of klass else return []
  # grant(named_class, named_priv)  - if named_class==klass return (named_priv + anything it implies) else return []
  def grantable_privileges_for_class(klass)
    return [] if !self.is_grant?
    return [] if self.class_name != 'any' && self.class_name != klass.name
    return klass.declared_privileges + [:any] if self.privilege == :any
    return [self.privilege] + klass.sg_priv_to_implied_privs[self.privilege]
  end

  # Returns true if this permission grants the given user (of the
  # given firm) the privilege op on obj.

  def allows?( obj, priv, user )

    return false if obj.class.sg_base_class_name != self.class_name
    return false if self.privilege != :any && self.privilege != priv && !(obj.class.sg_priv_to_implied_privs[self.privilege].include?(priv))
    return false if self.is_grant
    return allows_internal?( obj, user )

  end

  def allows_internal?( obj, user ) # :nodoc:

    if self.target_owned_by_self

      owner_ack = owner_access_control_key

      unless owner_ack.nil?
        owner_id = obj[ owner_ack ]
        return false if owner_id != user.id
      end

    end
      
    ack_checks_hash_internal.each do |obj_attr, val|
      return false if obj[obj_attr] != val
    end

    return true

  end

  private

  def ack_checks_hash_internal
    @internal_acks_hash ||= {}.tap do |ack_hash|
      target_class.access_control_keys.each do |obj_attr|
        target_attr = 'target_' + obj_attr
        target_attr_val = self[ target_attr ]
        unless target_attr_val.nil?
          ack_hash[obj_attr] = target_attr_val
        end
      end
    end
  end

  def owner_access_control_key
    @owner_ack_internal ||= target_class.owner_access_control_key
  end

  public

  # Returns true if this permission can grant the other_perm.
  # That is, if my_grant_perm.can_grant?( other_perm ), and the user
  # has my_grant_perm, they can add other_perm to a role.
  #
  # Because this is so confusing, here is a table:
  #
  # grant(any_class, any_priv)              - always true provided access control keys match
  # grant(any_class, named_priv) 
  #     other_priv(any_class, any_priv)     - always false
  #     other_priv(any_class, named_priv)   - assert grant.priv == other_priv.priv
  #     other_priv(named_class, any_priv)   - always false
  #     other_priv(named_class, named_priv) - assert grant.grantable_privileges_for_class(other_priv.class).include?(other_priv.priv)
  # grant(named_class, any_priv)
  #     other_priv(any_class, any_priv)     - always false
  #     other_priv(any_class, named_priv)   - always false
  #     other_priv(named_class, any_priv)   - assert grant.class == other_priv.class
  #     other_priv(named_class, named_priv) - assert grant.class == other_priv.class 
  # grant(named_class, named_priv)
  #     other_priv(any_class, any_priv)     - always false
  #     other_priv(any_class, named_priv)   - always false
  #     other_priv(named_class, any_priv)   - always false
  #     other_priv(named_class, named_priv) - assert ( grant.class == other_priv.class and 
  #                                             grant.grantable_privileges_for_class(other_priv.class).include?(other_priv.priv) )
  # If the above conditions all pass then assert access_control_keys match 
  #

  def can_grant?( other_perm )

    # check that self is in fact a grant
    return false if !self.is_grant
    return false if !self.has_grant_option && other_perm.is_grant
    return false if self.target_owned_by_self &&
                    !other_perm.target_owned_by_self
    
    # check target class and privilege
    if self.class_name == 'any'  # grant on any class
      if self.privilege != :any
        return false if other_perm.privilege == :any    
        if other_perm.class_name == 'any'
          return false unless self.privilege == other_perm.privilege
        else
          # if we have reached this condition we know that other_perm.class name must be a named class
          return false unless self.grantable_privileges_for_class(other_perm.target_class).include?(other_perm.privilege)
        end
      end
    else  # grant on a named class
      return false unless self.class_name == other_perm.class_name
      if self.privilege != :any 
        return false if other_perm.privilege == :any
        # if we have reached this condition we know that other_perm.class name must be a named class
        return false unless self.grantable_privileges_for_class(other_perm.target_class).include?(other_perm.privilege)
      end
    end

    # in all cases, access control keys must match
    self.class.target_access_control_keys.each do |attr|
      return false if !self.send( attr ).nil? &&
                      self.send( attr ) != other_perm.send( attr )
    end

    return true

  end

  # Permissions for permission objects themselves depend on grants,
  # so we need to special-case some of the usual API...

  def permits_action?( event_name, user = User.current )

    # event_name is actually ignored, per current policy;
    # they *all* require the same thing, a relevant grant...

    user.permissions.any?{ |grant| grant.can_grant?( self ) }

  end

  # return privileges that imply or are implied by self (includes self.privilege)
  def alternate_implied_privileges
    if self.class_name == 'any'
      return [self.privilege] 
    end
    klass = self.target_class
    return [self.privilege] + klass.sg_priv_to_implied_privs[self.privilege] + klass.sg_implied_priv_to_privs[self.privilege]
  end

  # If editing a role, the user might be able to replace the
  # privilege of this permission with others.  If so, this will
  # be the full list of alternatives.
  # What we really want here is the list of privs that imply or are implied by this one
  # PROVIDED that the current user has the power to grant them.

  def alternate_privileges_for_edit( user = User.current )
    applicable_grants = user.permissions.select{|grant| grant.can_grant?(self)}  # grants that could grant this priv
    candidate_privs = self.alternate_implied_privileges.flatten.uniq             # privs that imply or are implied by this one
    tmp_perm = self.clone
    candidate_privs.select { |p| applicable_grants.find {|g| tmp_perm.privilege = p; g.can_grant?(tmp_perm) } } # make sure user has the power to grant       
  end
    
end
