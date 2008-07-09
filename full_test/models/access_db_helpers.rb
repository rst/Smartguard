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
module ActiveRecord
  module ConnectionAdapters
    class AbstractAdapter

      # Convenience method --- declare the :owner_id and :owner_firm_id
      # columns in the table named 'table_name', and add conventional
      # indexes on them; most access-controlled tables will have these.

      def add_owner_access_control_keys_and_indexes_for( table_name )
        add_column table_name, :owner_id, :integer, 
          :foreign_key => {:table => :users, :name=>"fk_#{table_name}_owner"},
          :null => false
        add_column table_name, :owner_firm_id, :integer, 
          :foreign_key => {:table => :firms, 
                           :name => "fk_#{table_name}_firm"},
          :null => false

        # Try to avoid bumping up against Oracle name-length limits... 

        add_index table_name, :owner_id, 
          :name => "#{table_name}_by_owner"
        add_index table_name, :owner_firm_id, 
          :name => "#{table_name}_by_firm"
      end
    end
  end
end

module Access
  module Controlled
    module ClassMethods

      # :call-seq:
      #   owner_attrs_and_validations
      #   owner_attrs_and_validations :default_from_current_user => true,
      #      :include_privs => false
      #
      # Convenience method --- declare the :owner and :owner_firm
      # associations which most access-controlled models will have.
      #
      # Also typically adds the declarations
      #
      #   never_permit_anyone :to_update_attribute => :owner_firm_id
      #   require_privilege :reassign, :to_update_attribute => :owner_id
      #
      # Add ":include_privs => false" to *prevent these from being
      # added to the class (e.g., to set a different policy); they'll
      # be there by default.
      #
      # Typically invoked as a declaration in class definition:
      #
      #   class Utensil < ActiveRecord::Base
      #     include Access::Controlled
      #     owner_attrs_and_validations
      #     ...
      #   end
      #
      # If :default_from_current_user is set to true, the :owner
      # and :owner_firm

      def owner_attrs_and_validations( opt_args = {} )

        opt_args.keys.each do |k|
          unless [:default_from_current_user, :include_privs].include?( k )
            raise ArgumentError, 
              "Bad keyword #{k} to owner_attrs_and_validations"
          end
        end

        belongs_to :owner,      :class_name => 'User', 
                                :foreign_key => :owner_id
        belongs_to :owner_firm, :class_name => 'Firm', 
                                :foreign_key => :owner_firm_id

        validates_presence_of :owner
        validates_presence_of :owner_firm

        unless opt_args.has_key?( :include_privs ) && !opt_args[:include_privs]
          require_privilege :reassign, :to_update_attribute => [:owner_id]
          never_permit_anyone :to_update_attribute => [:owner_firm_id]
        end

        if opt_args[:default_from_current_user]
          before_validation_on_create do |rec|
            unless User.current.nil?
              rec.owner      = User.current      if rec.owner.nil?
              rec.owner_firm = User.current.firm if rec.owner_firm.nil?
            end
          end
        end
      end

    end
  end
end
