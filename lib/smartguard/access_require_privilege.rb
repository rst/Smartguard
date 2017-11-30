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
  module RequirePrivilege

    EVENT_CALLBACK_KEYS = { :create  => :before_create,
                            :find    => :after_find,
                            :update  => :before_update,
                            :destroy => :before_destroy }

    DEFAULT_DECLARED_PRIVILEGES = [ :permit_individually ]

    module ClassMethods

      # :call-seq:
      #   Klass.where_permits_action :action_name[, :user => ...]
      #
      # Returns the text of a SQL condition (suitable for use in a 
      # where clause) which selects records of this class's table
      # on which the user (default: User.current) is permitted to
      # perform the given action

      def where_permits_action( action, keyword_args = {} )
        priv = self.callback_privilege( EVENT_CALLBACK_KEYS[ action ] )
        if priv.nil?
          return '1 = 1'
        else
          return where_permits( priv, keyword_args )
        end
      end

      # :call-seq:
      #   Klass.ids_permitting_action :action_name[, :user => ...]
      #
      # Returns the text of a SQL subquery (suitable for use in a 
      # join, etc.) which selects ids of records of this class's table
      # on which the user (default: User.current) is permitted to
      # perform the given action

      def ids_permitting_action( action, keyword_args = {} )
        priv = self.callback_privilege( EVENT_CALLBACK_KEYS[ action ] )
        if priv.nil?
          return '(select id from #{table_name})'
        else
          return ids_permitting( priv, keyword_args )
        end
      end

      # :call-seq:
      #   Klass.where_permits_update_attr :action_name[, :user => ...]
      #
      # Returns the text of a SQL condition (suitable for use in a 
      # where clause) which selects records of this class's table
      # on which the user (default: User.current) is permitted to
      # update the given attributes

      def where_permits_update_attr( attr_name, keyword_args = {} )
        priv = self.reflected_privilege( :update_attribute, attr_name )
        if priv.nil?
          return '1 = 1'
        else
          return where_permits( priv, keyword_args )
        end
      end

      # :call-seq:
      #   Klass.where_permits_update_attr :action_name[, :user => ...]
      #
      # Returns the text of a SQL subquery (suitable for use in a 
      # join, etc.) which selects ids of records of this class's table
      # on which the user (default: User.current) is permitted to
      # update the given attributes

      def ids_permitting_update_attr( attr_name, keyword_args = {} )
        priv = self.reflected_privilege( :update_attribute, attr_name )
        if priv.nil?
          return '(select id from #{table_name})'
        else
          return ids_permitting( priv, keyword_args )
        end
      end

      # :call-seq:
      #   (in class definition)
      #   declare_privilege :privilege, :privilege2, ...
      #        e.g.
      #   declare_privilege :bake, :baste, :fricassee, :saute, ...
      #
      # Puts the operations on a list of known privileges for the
      # class which are controlled by the RBAC system.  Privileges
      # will typically name an operation or set of operations.
      #
      # The list may be retrieved by calling Klass.declared_privileges
      
      def declare_privilege *args
        args.each do |arg| 
          if !arg.is_a?( Symbol )
            raise ArgumentError, 
              "Attempt to declare #{arg.inspect}, not a symbol, " +
              "as a privilege"
          end
          unless declared_privileges.include?( arg )
            write_inheritable_array( :declared_privileges, [arg] )
          end
        end
      end

      # :call-seq:
      #   (in class definition)
      #   require_privilege :privelege, 
      #     :on_associated => attr,
      #     :to_invoke               => [:method, :method, ...],
      #     :to_initialize_attribute => [:attr, :attr, ...],
      #     :to_update_attribute     => [:attr, :attr, ...],
      #     :to_set_attribute        => [:attr, :attr, ...],
      #     :to_access_attribute     => [:attr, :attr, ...],
      #     :to_associate_as         => ["Class#assoc_name", ...],
      #     :to_dissociate_as        => ["Class#assoc_name", ...],
      #     :at_callback             => {:after_find, :before_create, ... },
      #     :for_action              => {:create, :find, :update, :destroy}
      #
      # 'require_privilege' arranges to auto-generate wrapper
      # code which will cause permissions to be checked before
      # the model code performs certain actions.  
      #
      # The generated code usually checks for permissions declared
      # on the object itself.  However, :on_associated requests
      # permission checks be performed on some associated object,
      # named by an attribute.  Thus for instance, 
      #
      #   class Post
      #     belongs_to :blog
      #     require_privilege :edit_post, :on_associated => :blog,
      #       :to_set_attribute => [:text]
      #     ...
      #   end
      #
      # will prohibit setting the text of a post unless the
      # user has an 'edit_post' permission on the associated blog.
      # If the association isn't set up, all such checks fail.
      # (Without :on_associated, this would check for the :edit_post
      # privilege on posts).
      #
      # Other keywords add specific restrictions, as follows:
      #
      # [:to_invoke]
      #   "method or methods" is a list of symbols
      #   naming instance methods of the class (or just a symbol,
      #   again naming an instance method).  Arranges that before
      #   invoking those methods, we first do 
      #
      #     self.check_permission! :privilege
      #
      #   throwing the PermissionFailure exception if User.current
      #   does not have permission to perform the operation.
      #
      #   This may not work for private methods; that's not a bug,
      #   as this is intended to guard public APIs.  
      #
      # [:to_set_attribute]
      #    value is the name of a single attribute (as a symbol, e.g. :name), 
      #    or a list of attributes (e.g., [:name, :review_date, :status]).  
      #    This arranges to put check_permission! guards on invocations
      #    of the attribute's setter methods (e.g., :name=, :review_date=, 
      #    :status=).  
      #
      #    Note that attempting to set an attribute to the value it already
      #    has will _not_ result in a permissions check.  (There are points
      #    at which Rails does this internally, which would yield spurious
      #    permission failures if we did these checks).
      #
      # [:to_update_attribute]
      #    As :to_set_attribute, but only does the checks for saved objects
      #    (those for which :new_record? returns false).  So, for instance,
      #
      #      require_privilege :edit_post, :to_update_attribute => :entry_txt
      #
      #    would require the :edit_post privilege only if someone is trying
      #    to update the text of an existing post, but would allow them
      #    to initialize the text of a new, unsaved one.
      #
      # [:to_initialize_attribute]
      #    The opposite of :to_update_attribute --- permission checks are
      #    performed only when the attribute(s) are set on _unsaved_ objects.
      # 
      # [:to_access_attribute]
      #    guards all writes (as :to_set_attribute), and reads as well,
      #    e.g. by obj.attr, obj.attr?, etc.
      #
      # All of these work on attributes which shadow database columns, 
      # and those that don't (e.g., declared by attr_accessor).  The only
      # known bug is that if you're using +composed_of+, you should guard
      # the composite pseudo-attribute, _not_ the component attributes
      # corresponding to individual database columns.
      #
      # [:to_associate_as, :to_dissociate_as]
      #   These next two options add permission checks on operations
      #   on a _different_ class.  A typical case would be
      #
      #      class BlogEntry
      #        include Access::Controlled
      #        belongs_to :blog
      #      end
      #
      #      class Blog
      #        include Access::Controlled
      #        require_privilege :post, 
      #           :to_associate_as  => ['BlogEntry#blog']
      #        require_privilege :delete_post, 
      #           :to_dissociate_as => ['BlogEntry#blog']
      #      end
      #
      #   This causes the following permission checks:
      #
      #   * when a blog is assigned to a blog_entry, as by, e.g.,
      #
      #        BlogEntry.new    :blog => some_blog, ...
      #        BlogEntry.create :blog => some_blog, ...
      #        blog_entry.blog = some_blog
      #        blog_entry.blog_id = params[...][:blog_id]
      #
      #     :to_associate_as arranges that
      #     we first do some_blog.check_permission!( :post ),
      #     before actually changing the association.  (For the
      #     +blog_id+ case, this is actually implemented by a
      #     check within the database, to avoid the full expense
      #     of loading the object).
      #
      #   * when some_blog is _already_ the blog of some_entry,
      #     and we do any of
      #
      #        some_entry.blog = some_other_blog
      #        some_entry.update_attribute :blog, some_other_blog
      #        some_entry.destroy
      #
      #     :to_dissociate_as arranges that
      #     we first do some_blog.check_permission!( :delete_post ),
      #     before actually performing the operation.
      #
      #   These options are not compatible with :on_associated.
      #
      # [:at_callback]
      #   Arranges for a privilege check whenever the
      #   given active record callback is invoked.  Most standard
      #   callbacks should be supported.  See the Rails docs for
      #   available callbacks, or +require_eponymous_privilege_to+
      #   and +require_privilege :for_action+, q.v., which provide
      #   more readable versions of the usual use cases for this.
      #
      # [:for_action]
      #   Arranges that at the named points of the object lifecycle,
      #   (say, :create) we perform a permission check to see if the
      #   user has the privilege of the same name (that is, if there's
      #   a permission that grants him :create privilege on the record).
      #
      #   The lifecycle points are:
      #
      #   [+:create+] first save of a new object, after its attributes
      #               have all been set.  (You can create an object
      #               with any attribute values you like in core, but
      #               saving it and making it available to others
      #               requires a permission check)
      #
      #   [+:find+]   We check for +:find+ permission after retrieving
      #               an object from the database.  The overhead can
      #               be considerable for queries returning large
      #               numbers of records.
      #
      #   [+:update+] save of an object that already existed in the db.
      #
      #   [+:destroy+] what it says.
      #
      #   These are implemented by hanging permission checks on the
      #   +:before_create+, +:after_find+, +:before_update+, and 
      #   +:before_destroy+ active record callbacks, using 
      #   +require_privilege :at_callback+.

      def require_privilege privilege, key_args

        declare_privilege privilege unless key_args[ :on_associated ]
        require_privilege_internal privilege, key_args

      end

      # :call-seq:
      #   (in class definition)
      #   never_permit_anyone
      #     :to_update_attribute     => [:attr, :attr, ...],
      #     :to_initialize_attribute => [:attr, :attr, ...],
      #     :at_callback => {:after_find, :before_create, ... }
      #     :for_action              => {:create, :find, :update, :destroy}
      #
      # Supported arguments are as for require_privilege (q.v.),
      # but this function arranges that the permission check
      # _always_ fails.  So, for instance,
      #
      #   never_permit_anyone :to_update_attribute => :name
      #
      # would prevent anyone from changing the name of a record
      # that had already been saved, and
      #
      #   never_permit_anyone :at_callback => :before_update
      #
      # would keep any preexisting record from ever getting
      # updated at all.

      def never_permit_anyone key_args
        valid_keys = [:to_update_attribute, :to_initialize_attribute, 
                      :at_callback, :for_action]
        key_args.each do |k,v|
          unless valid_keys.include?( k )
            raise ArgumentError, 
              "#{k.inspect} not a valid keyword for never_permit_anyone"
          end
        end
        require_privilege_internal :forbidden_operation, key_args
      end

      def require_privilege_internal privilege, key_args # :nodoc:

        to_invoke     = hack_rp_arg( key_args.delete( :to_invoke ))
        to_access     = hack_rp_arg( key_args.delete( :to_access_attribute ))
        to_initialize = hack_rp_arg( key_args.delete(:to_initialize_attribute))
        to_update     = hack_rp_arg( key_args.delete( :to_update_attribute ))
        to_set        = hack_rp_arg( key_args.delete( :to_set_attribute ))
        to_assoc      = hack_rp_arg( key_args.delete( :to_associate_as ))
        to_dissoc     = hack_rp_arg( key_args.delete( :to_dissociate_as ))
        at_callback   = hack_rp_arg( key_args.delete( :at_callback ))
        for_action    = hack_rp_arg( key_args.delete( :for_action ))

        on_assoc    = key_args.delete( :on_associated )

        priv_key    = on_assoc ? [ privilege, on_assoc ] : privilege

        event_callbacks = for_action.collect do |ev_name| 
          callback = EVENT_CALLBACK_KEYS[ev_name] 
          raise ArgumentError, "Unknown event #{ev_name}" if callback.nil?
          callback
        end

        at_callback = at_callback + event_callbacks

        at_callback.each do |callback|
          set_reflected_privilege( :at_callback, callback, priv_key )
        end

        to_assoc.each do |assoc_key|
          set_reflected_privilege( :associate, assoc_key, priv_key )
        end

        to_dissoc.each do |assoc_key|
          set_reflected_privilege( :dissociate, assoc_key, priv_key )
        end

        to_access.each do |attr_name|
          set_reflected_privilege( :read_attribute, attr_name, priv_key )
        end

        (to_initialize + to_set + to_access).each do |attr_name|
          set_reflected_privilege( :initialize_attribute, attr_name, priv_key )
        end

        (to_update + to_set + to_access).each do |attr_name|
          set_reflected_privilege( :update_attribute, attr_name, priv_key )
        end

        if !on_assoc.nil? && (to_assoc + to_dissoc).size > 0
          raise ArgumentError, 
            "Sorry can't do :on_associated with :to_associate permissions"
        end

        if key_args.size > 0
          raise ArgumentError, 
            "Unrecognized arguments #{key_args.keys.inspect} " + 
            "to require_privilege"
        end

        set_guarded_attrs = to_initialize + to_update + to_set + to_access
        setter_methods = set_guarded_attrs.collect do |attr_name|
          (attr_name.to_s + '=').to_sym
        end

        all_methods = (to_invoke + to_access + setter_methods)

        all_methods.sort_by( &:to_s ).uniq.each do |meth|
          if meth.to_s[-1,1] != '='
            wrapper = <<-EOV
              def #{meth.to_s} ( *args, &block )
                check_permission! #{priv_key.inspect}
                #{wrapped_name( meth )}( *args, &block )
              end
            EOV
            wrap_now_or_later meth, wrapper
          else
            # Setters are forbidden (by the grammar(!)) from
            # taking blocks or multiple arguments...
            meth_str = meth.to_s
            attr = (meth_str[0..meth_str.size-2]).to_sym
            wrapper = <<-EOV
              def #{meth.to_s} ( arg )
                check_attr_write_permission!( #{attr.inspect}, arg )
                self.send :#{wrapped_name( meth )}, arg
              end
            EOV
            wrap_now_or_later meth, wrapper
          end
        end

        at_callback.each do |callback|
          callback = callback.to_sym
          if callback == :after_find || callback == :after_initialize
            if !self.method_defined?( callback )
              define_method( callback ){}
            end
          end
          if callback == :before_update
            self.send( callback, lambda do |rec| 
                         ActiveSupport::Deprecation.silence do
                           rec.check_permission!( priv_key ) if rec.changed?
                         end
                       end)
          else
            self.send( callback, lambda do |rec| 
                         rec.check_permission!( priv_key )
                       end)
          end
        end

      end

      # :call-seq:
      #   require_eponymous_privilege_to :create, :find, :update, :destroy
      #
      # An abbreviation for common uses of +require_privilege :for_action+.
      #
      #   require_eponymous_privilege_to :create, :destroy
      #
      # is just shorthand for
      #
      #   require_privilege :create,  :for_action => :create
      #   require_privilege :destroy, :for_action => :destroy
      #

      def require_eponymous_privilege_to *args

        args.each do |arg|
          callback = EVENT_CALLBACK_KEYS[ arg ]
          if callback.nil?
            raise ArgumentError, 
              "require_eponymous_privilege can't handle #{arg}"
          end
          require_privilege arg, :at_callback => callback
        end
        
      end

      # belongs_to wrapper which arranges for permissions to be
      # checked at appropriate points.

      def belongs_to( assoc_name, scope = nil, options = nil ) #:nodoc:

        if options.nil?
          super( assoc_name, scope )
        else
          super( assoc_name, scope, options)
        end

        raise "huh?" unless self.method_defined?( assoc_name )

        reflection = self.reflect_on_association( assoc_name )
        fk = reflection.foreign_key.to_sym

        setter_method     = (assoc_name.to_s + '=').to_sym
        old_setter_method = (assoc_name.to_s + '_without_assoc_chks=').to_sym
        alias_method old_setter_method, setter_method

        set_reflected_privilege( :fk_for_associate, fk, assoc_name.to_sym )
        set_reflected_privilege( :klass_for_associate, assoc_name.to_sym,
                                 self.name )

        define_method setter_method do |arg|

          klass = self.class.class_for_associate(assoc_name)
          rec_class_name = self.class.base_class_for_associate(assoc_name)
          
          if !klass.respond_to?( :associate_privilege )
            return( send old_setter_method, arg )
          end

          assoc_priv  = klass.associate_privilege(rec_class_name, assoc_name)
          dissoc_priv = klass.dissociate_privilege(rec_class_name, assoc_name)

          if !dissoc_priv.nil?
            old_associate = self.send assoc_name
            if !old_associate.nil?
              old_associate.check_permission!( dissoc_priv )
            end
          end

          if !assoc_priv.nil? && !arg.nil?
            arg.check_permission!( assoc_priv )
          end

          begin
            @smartguard_checked_associate = arg
            send old_setter_method, arg
          ensure
            @smartguard_checked_associate = nil
          end
          
        end

        self.before_destroy do |rec|

          klass = rec.class.class_for_associate(assoc_name)
          rec_class_name = rec.class.base_class_for_associate(assoc_name)

          if !klass.respond_to?( :associate_privilege )
            true
          else
            dissoc_priv = klass.dissociate_privilege(rec_class_name, 
                                                     assoc_name)
            if !dissoc_priv.nil?
              old_associate = rec.send assoc_name
              if !old_associate.nil?
                old_associate.check_permission!( dissoc_priv )
              end
            end
          end
        end
      end

      # Declares blocks of attributes to be set before others in attributes=
      # 
      # The problem we're trying to solve here is, say:
      # 
      #   Blog.create :owner => ..., :name => ...
      #
      # where the name attribute is guarded by require_privilege :to_update.
      # If :owner is not set first, the permission check will fail.  So, we
      # have to set up the access control keys before the other attributes.
      #
      # (In general, it's possible for an attribute to be *both* settable
      # *and* an access control key --- imagine a "published" flag which
      # governs read access for some users, and a "publish" privilege
      # which allows an editor to set the attribute.  In this case, we'd
      # want two blocks of "early privileges", one for the access control
      # keys that determine whether you can publish, and one for the 
      # published flag itself, followed by the ordinary attributes).

      def declare_attribute_block_set_groups( *groups )
        self.attribute_block_set_groups = groups
      end

      def attribute_block_set_groups # :nodoc:
        []                           # overridden by class_attribute stuff
      end

      # Returns true if the user could ever create an object
      # of this class.  
      #
      # Ordinarily checks two ways that permission could be denied:
      # 
      # * The class may +:require_privilege ... :for_action => create+
      #   (or equivalently, +:at_callback => :before_create+).
      #   
      #   If so, we require that the user has that required permission.
      #
      # * The class may have foreign keys declared with +:null => false+
      #   and with a +:to_associate+ permission on the foreign side.

      def permits_create?( user = User.current )

        # Check :before_create callback on this class, if any

        priv = self.callback_privilege( :before_create )

        unless priv.nil?
          if !priv.is_a?( Array )
            klass = self
          else
            klass = class_for_associate( priv.last )
            priv = priv.first
          end

          klass.check_user_set!( user, priv, nil )
          return false unless user.could_ever?( priv, klass )
        end

        # Check associates...

        reflect_on_all_associations( :belongs_to ).each do |assoc|

          foreign_key = assoc.foreign_key.to_s # sigh...
          column_desc = columns.detect { |col| col.name == foreign_key }

          # If the column is a foreign key with a NOT NULL constraint,
          # and permissions are required to set up the association,
          # make sure we could conceivably set it up.
          #
          # If the foreign key could be null, we don't need this check.

          if !column_desc.null  # null, yes, null.  NOT nil?
            klass = class_for_associate( assoc.name )
            assoc_base_klass = base_class_for_associate( assoc.name )
            assoc_priv = klass.associate_privilege( assoc_base_klass, assoc.name )
            klass.check_user_set!( user, assoc_priv, nil )
            return false if !assoc_priv.nil? && 
                            !user.could_ever?( assoc_priv, klass )
          end
          
        end

        # All checks passed

        return true

      end

      # Hooks invoked by various permission checks

      def class_for_associate( assoc_name ) # :nodoc:
        @classes_for_associates ||= {}
        @classes_for_associates[assoc_name] ||= 
          self.reflect_on_association(assoc_name).class_name.constantize
      end

      def base_class_for_associate( assoc_name ) # :nodoc:
        reflected_privilege( :klass_for_associate, assoc_name.to_sym )|| self.name
      end

      def associate_privilege( foreign_class_name, association_name ) # :nodoc:
        reflected_privilege( :associate,
                             foreign_class_name + '#' + association_name.to_s )
      end

      def dissociate_privilege( foreign_class_name, association_name )
        reflected_privilege( :dissociate,
                             foreign_class_name + '#' + association_name.to_s )
      end

      def read_attr_privilege( attr_name ) # :nodoc:
        reflected_privilege( :read_attribute, attr_name )
      end

      def callback_privilege( callback_name ) # :nodoc:
        reflected_privilege( :at_callback, callback_name )
      end

      def reflected_privilege( type, key ) # :nodoc:
        sg_reflected_privileges[[type,key]]
      end

      def association_access_control_keys
        sg_reflected_privileges.keys.select{|k| k.first == :fk_for_associate }.
          collect{ |k| k.second }
      end

      private

      def hack_rp_arg( arg )
        case arg
        when String     then [arg]
        when Enumerable then arg
        when nil        then []
        when Symbol     then [arg]
        else raise ArgumentError, 
          "Funny #{arg.inspect} in args to require_permission"
        end
      end
      
      def set_reflected_privilege( type, key, new_value )
        k = [type, key]
        old_value = sg_reflected_privileges[k]
        if old_value.nil?
          write_inheritable_hash( :sg_reflected_privileges, { k => new_value })
        elsif new_value != old_value
          raise ArgumentError,
            "Declaring #{new_value.inspect} as reflected privilege for " +
            "#{type}[#{key.inspect}], but already had #{old_value.inspect}"
        end
      end

      def wrap_now_or_later( meth_name, wrapper_code )
        if self.method_defined?( meth_name )
          wrap_method meth_name, wrapper_code
        else
          write_inheritable_hash( :sg_deferred_permission_wrappers,
                                  meth_name => wrapper_code )
        end
      end

      def method_added( meth_name )

        wrappers = read_inheritable_attribute :sg_deferred_permission_wrappers 
        return if wrappers.nil?

        # Note that the wrapper code redefines the method, so
        # the following rigamarole is needed to guard against
        # infinite recursion...

        @sg_deferred_wrappers_installed ||= []
        return if @sg_deferred_wrappers_installed.include?( meth_name )
        @sg_deferred_wrappers_installed << meth_name

        # OK, haven't *already* done the wrap thing for this method.
        # So, if it does have a declared wrapper, install it.

        wrapper_handler = wrappers[ meth_name ]
        wrap_method meth_name, wrapper_handler if !wrapper_handler.nil?

      end

      def wrap_method( meth_name, wrapper_code )
        alias_method wrapped_name( meth_name ), meth_name
        class_eval wrapper_code
      end

      def wrapped_name( meth_name )
        meth_name, suffix = meth_name.to_s.sub(/([?!=])$/, ''), $1
        (meth_name + '_without_permissions' + suffix.to_s).to_sym
      end

    end

    module InstanceMethods

      # attributes= wrapper which honors attribute_block_set_groups
      # (from the class level)

      def assign_attributes( new_attributes )  # :nodoc:

        return if new_attributes.nil?
        new_attrs = sanitize_for_mass_assignment(new_attributes).dup
        new_attrs.stringify_keys!

        self.class.attribute_block_set_groups.each do |blok|
          blok_attrs = {}
          blok.each do |attr|
            if new_attrs.has_key?( attr )
              blok_attrs[ attr ] = new_attrs.delete( attr )
            end
          end
          if blok_attrs.size > 0
            super blok_attrs
          end
        end

        super new_attrs
        
      end

      def attributes=( new_attributes )
        assign_attributes( new_attributes )
      end

      # Returns the normal permissions with any items which are 
      # access control keys

      def attributes_sans_access_control_keys
        acl_keys = self.class.access_control_keys + 
          self.class.association_access_control_keys
        acl_keys.map!{|x| x.to_s}
        self.attributes.reject{|k, v| acl_keys.include?(k.to_s)}
      end

      # Returns true if the user has permission to update attribute attr,
      # named by a symbol, e.g. blog.permits_update_attr?( :name )

      def permits_update_attr?( attr, user = User.current )
        priv = set_attr_privilege( attr )
        return priv.nil? || self.permits?( priv, user )
      end

      # Returns true if the user has permission to run a callback,
      # e.g., blog.permits_at_callback?( :before_create )

      def permits_at_callback?( callback_name, user = User.current )
        priv = self.class.callback_privilege( callback_name )
        return priv.nil? || self.permits?( priv, user )
      end

      # Returns true if the user has permission to cause the specific
      # action, in the sense of +require_privilege :for_action+
      # e.g., blog.permits_action?( :update ).  
      #
      # If the action is :destroy, we also check whether some associated
      # object (via :belongs_to) has a :to_dissociate_as requirement that
      # would prevent destruction.
      #
      # See also permits_create? at the class level.

      def permits_action?( event_name, user = User.current )

        callback_name = EVENT_CALLBACK_KEYS[ event_name ]
        priv = self.class.callback_privilege( callback_name )
        self_permits = priv.nil? || self.permits?( priv, user )

        return false if !self_permits
        return self_permits unless event_name == :destroy

        self.class.reflect_on_all_associations( :belongs_to ).each do |assoc|
          klass = self.class.class_for_associate( assoc.name )
          base_klass = self.class.base_class_for_associate( assoc.name )
          dissoc_priv = klass.dissociate_privilege( base_klass, assoc.name )
          if !dissoc_priv.nil?
            associate = self.send assoc.name
            if !associate.nil?
              return false unless associate.permits?( dissoc_priv, user )
            end
          end
        end

        return true
        
      end

      # :call-seq:
      #    obj.permitted_associates :association_name
      #    obj.permitted_associates :association_name
      #                             :conditions => ['name like ?', name]
      #    obj.permitted_associates :association_name, :include => ...
      #    etc.
      #
      # If, say, we have:
      #
      #   class Blog; belongs_to :owner_firm; end
      #
      # then +some_blog.permitted_associates :owner_firm+ will return
      # all firms that would allow us to do:
      #
      #   blog.owner_firm = the_firm
      #   blog.save!
      #
      # without a PermissionFailure.  
      #
      # Additional keyword arguments may be supplied.  
      #
      # If :conditions are supplied, they augment the
      # permitted_associates conditions, so the 'name like ?' example
      # above will return only permitted firms whose name matches the
      # pattern.
      #
      # Other keyword arguments are passed unaltered to the underlying
      # +find+ operation.
      #
      # As a matter of implementation detail, there are three requirements
      # that a permitted associate must meet:
      #
      # * If the association's foreign key (e.g. 'owner_firm_id') is also
      #   an access control key, and the object's class (e.g. 'Blog' above)
      #   requires permission for_action +:create+, or +:update+, we look at
      #   the values given for +owner_firm_id+ in User.current's +:create+ or
      #   +:update+ permissions on the +Blog+ class.
      #
      # * Alternatively +Firm+ may +require_privilege+ +:to_associate_as+
      #   +'Blog#owner_firm_id'+ --- in which case, we look for firms on
      #   which User.current has the relevant privilege.
      #
      # If both the above checks apply, we only return firms that pass
      # both tests.  Finally:
      #
      # * +Firm+ may +require_privilege+ +:to_dissociate_as+
      #   +'Blog#owner_firm_id'+ --- which can keep us from changing the
      #   association, once it is already set.  If such a condition applies,
      #   then the current value for the associate is the _only_ permitted
      #   value.

      def permitted_associates( assoc_name, opts = {} )

        # Start with SQL condtions supplied by the user, if any

        sql_conds = []
        opts = opts.dup
        if opts.has_key?( :conditions )
          sql_conds << sanitize_sql( opts.delete( :conditions ))
        end
        user = opts.delete( :for_user ) || User.current

        # Next, add check for the current-associate special case,
        # if it applies...

        klass = self.class.class_for_associate( assoc_name )
        if klass.nil?
          raise ArgumentError, "No belongs_to #{assoc_name} for this class"
        end
        
        dissoc_priv = klass.dissociate_privilege( self.class.name, assoc_name )

        unless dissoc_priv.nil?
          current_associate = self.send assoc_name
          unless current_associate.permits?( dissoc_priv, user )

            # Don't just return [current_associate] here out of fanatical
            # devotion to correctness --- it may not meet additional
            # conditions supplied by the user, in which case the correct
            # return value is [].

            sql_conds << sanitize_sql( [ 'id = ?', current_associate.id ] )
          end
        end

        # Next, add check for :to_associate privilege, if any

        rec_class_name = self.class.base_class_for_associate(assoc_name)
        assoc_priv = klass.associate_privilege( rec_class_name, assoc_name )
        
        unless assoc_priv.nil?
          sql_conds << klass.where_permits( assoc_priv, user )
        end

        # Lastly, if foreign key is an access control key, and we don't
        # have wildcard permissions, then only certain values will allow
        # a save...

        reflection = self.class.reflect_on_association( assoc_name )
        foreign_key = reflection.foreign_key.to_s

        if self.class.access_control_keys.include?( foreign_key )

          save_event_type = new_record? ? :create : :update

          callback_name = EVENT_CALLBACK_KEYS[ save_event_type ]
          privilege = self.class.callback_privilege( callback_name )

          perm_access_key = 'target_' + foreign_key

          is_owner_ack = (foreign_key == self.class.owner_access_control_key)

          unless privilege.nil?

            all_perms = user.all_permissions( privilege, self.class )
            real_perms = all_perms.reject {|p| p.is_grant?}
            all_ids = real_perms.collect{ |perm| 
              if is_owner_ack && perm.target_owned_by_self
                user.id
              else
                perm[perm_access_key] 
              end
            }

            if all_ids == []
              sql_conds << '2 + 2 = 5'
            elsif !all_ids.any?{ |id| id.nil? }
              sql_conds << sanitize_sql([ "#{klass.table_name}.id in (?)",
                                          all_ids ])
            end
            
          end
          
        end

        # Now have a bunch of conditions, and 'em together and do it...

        real_conds = sql_conds.join( ' and ' )

        return klass.applying_deprecated_query_args( opts ).where( real_conds )

      end

      # Support reflection

      # Returns the privilege (if any) needed to initialize attribute
      # attr_name (as a symbol)

      def initialize_attr_privilege( attr_name )
        self.class.reflected_privilege( :initialize_attribute, attr_name )
      end

      # Returns the privilege (if any) needed to update attribute
      # attr_name (as a symbol)

      def update_attr_privilege( attr_name )
        self.class.reflected_privilege( :update_attribute, attr_name )
      end

      # Returns the privilege (if any) needed to set attribute
      # attr_name (as a symbol).  For an unsaved object, this is the
      # same as 'initialize_attr_privilege'; for a saved object, it
      # is the same as 'update_attr_privilege'.

      def set_attr_privilege( attr_name )
        how = self.new_record? ? :initialize_attribute : :update_attribute
        self.class.reflected_privilege( how, attr_name )
      end

      # Add permissions checks to some innards...

      def read_attribute( attr_name )
        priv = self.class.read_attr_privilege( attr_name.to_sym )
        self.check_permission!( priv ) unless priv.nil?
        super
      end

      def query_attribute( attr_name )
        priv = self.class.read_attr_privilege( attr_name.to_sym )
        self.check_permission!( priv ) unless priv.nil?
        super
      end

      def read_attribute_before_type_cast( attr_name )
        priv = self.class.read_attr_privilege( attr_name.to_sym )
        self.check_permission!( priv ) unless priv.nil?
        super
      end

      private

      def sanitize_sql( args )
        self.class.send :sanitize_sql, args
      end

      def smartguard_set_attrs_for_copy!( attrs )

        unless new_record?
          raise ArgumentError, 
                "Can't call set_attrs_for_copy on existing record"
        end

        begin
          @smartguard_attr_write_checks_suppressed = true
          attrs.each do |k,v|
            self.send("#{k}=",v)
          end
        ensure
          @smartguard_attr_write_checks_suppressed = false
        end

      end

      def _write_attribute( attr_name, value )
        check_attr_write_permission!( attr_name, value )
        super
      end

      def check_attr_write_permission!( attr_name, new_value )

        return if @smartguard_attr_write_checks_suppressed

        old_value = read_attribute( attr_name )

        return if old_value.to_s == new_value.to_s

        # Re: oddness that follows -- 'set_attr_privilege' calls
        # 'new_record?', which can in turn call 'write_attribute'
        # to unwind transaction state, leading to infinite loops.
        # Since we assume that the prior state was safe, anyway,
        # we just let activerecord unwind (if it's going to do
        # that) without interfering.

        priv = begin
                 @smartguard_attr_write_checks_suppressed = true
                 set_attr_privilege( attr_name.to_sym )
               ensure
                 @smartguard_attr_write_checks_suppressed = false
               end

        self.check_permission!( priv ) unless priv.nil?

        assoc_name = self.class.reflected_privilege( :fk_for_associate, 
                                                     attr_name.to_sym )

        unless assoc_name.nil?

          klass = self.class.class_for_associate( assoc_name )

          if klass.respond_to?( :associate_privilege ) &&
              (@smartguard_checked_associate.nil? ||
               !@smartguard_checked_associate.is_a?( klass ) ||
               !new_value == @smartguard_checked_associate.id)

            check_foreign_priv = lambda do |priv, foreign_id|
              if !priv.nil? && !foreign_id.nil?
                log_hash = {
                  :model_class => klass.name,
                  :model_id    => foreign_id,
                  :privilege   => priv.to_s,
                  :user_id     => User.current.id,
                  :user_name   => User.current.name
                }
                if klass.permits_for_id?( priv, foreign_id )
                  log_hash[:success] = true
                  Smartguard::Logging.log( log_hash )
                else
                  log_hash[:success] = false
                  Smartguard::Logging.log( log_hash )
                  raise PermissionFailure.new("Not authorized to #{priv} on #{klass}",
                                              :privilege => priv,
                                              :target_class => klass, 
                                              :target => foreign_id)
                end
              end
            end

            rec_class_name = self.class.base_class_for_associate(assoc_name)
            assoc_prv  = klass.associate_privilege( rec_class_name, 
                                                    assoc_name )
            dissoc_prv = klass.dissociate_privilege( rec_class_name, 
                                                     assoc_name )

            check_foreign_priv.call( dissoc_prv, old_value )
            check_foreign_priv.call( assoc_prv,  new_value )
          
          end

        end

      end

    end

  end
end
