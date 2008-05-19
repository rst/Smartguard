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

  module Sensitive

    # Mixin to add access-sensitive behavior to any FormBuilder class.
    # Causes all input helpers to generate disabled inputs if the
    # current user does not have permission to change the underlying
    # model attribute.

    module FormBuilderMixin

      # explicitly list helpers we wrap; there's a test that
      # compares this to what ActiveRecord defines to see if
      # there might be something new in this version of Rails
      # that was missed.

      SIMPLE_FORM_HELPERS = 
        %w(file_field text_area password_field hidden_field text_field
           datetime_select time_select date_select)

      OTHER_FORM_HELPERS = 
        %w(check_box radio_button 
           select country_select collection_select time_zone_select)

      JUNK_METHODS = %w(fields_for error_message_on error_messages
                        apply_form_for_options! label submit)

      CHECKMARK = '&#10003;'    # HTML code for a check-mark

      module ClassMethods
        def wrap_form_helper_for_permissions( helper_name, args,
                                              display_val_code = 'val.to_s'
                                              )
          wrapped_helper_name = (helper_name + '_without_permissions')
          alias_method wrapped_helper_name, helper_name
          args_without_inits = 
            args.gsub(/\s*=[^,]*,/, ',').gsub(/\s*=[^,]*$/, '')
          code = <<-EOV
            def #{helper_name} (#{args})
              if @object.permits_update_attr?( attr )
                #{wrapped_helper_name}( #{args_without_inits} )
              else
                inp_flag = @options[:if_not_permitted] || :disable
                case inp_flag
                when :disable :
                  saved_object_name = @object_name
                  begin
                    @object_name=('disabled_'+saved_object_name.to_s).to_sym
                    html_options = html_options.merge :disabled => true
                    #{wrapped_helper_name}( #{args_without_inits} )
                  ensure
                    @object_name = saved_object_name
                  end
                when :present_text :
                  val = @object.send attr
                  #{display_val_code}
                else
                  raise ArgumentError, 
                    "Invalid :if_not_permitted option, " + inp_flag.inspect
                end
              end
            end
          EOV
          class_eval code
        end
      end

      def self.included( klass )

        # The usual hook for ClassMethods

        klass.extend ClassMethods

        # Wrap each simple helper in a permission test...

        SIMPLE_FORM_HELPERS.each do |helper|
          klass.wrap_form_helper_for_permissions helper,
            'attr, html_options = {}'
        end

        # Sigh... defaults here not quoted strings (differing from
        # base Rails behavior) to avoid type_cast crud...

        klass.wrap_form_helper_for_permissions 'check_box',
          'attr, html_options = {}, checked_value=1, unchecked_value=0',
          '(val == checked_value)? CHECKMARK : ""'

        klass.wrap_form_helper_for_permissions 'radio_button',
          'attr, tag_value, html_options = {}',
          '(val == tag_value)? CHECKMARK : ""'

        klass.wrap_form_helper_for_permissions 'select', 
          'attr, choices, options = {}, html_options = {}',
          'find_selected_option_text( val, choices )'

        # Also assuming that what comes out of .to_s on a TimeZone
        # object is human-readable... dates are more of a problem,
        # but this isn't great.

        klass.wrap_form_helper_for_permissions 'time_zone_select',
          'attr, priority_zones = nil, options = {}, html_options = {}'

        klass.wrap_form_helper_for_permissions 'country_select',
          'attr, priority_countries = nil, options = {}, html_options = {}'

        klass.wrap_form_helper_for_permissions 'collection_select', 
          'attr, collection, value_attr, text_attr, opts={}, html_options={}',
          'find_selected_option_from_collection(val, collection, '+
            'value_attr, text_attr)'
      end

      def find_selected_option_from_collection( val, collection, 
                                                value_meth, text_meth )

        return '' if val.nil?

        collection.each do |elt|
          if elt.send( value_meth ) == val
            return elt.send( text_meth )
          end
        end

        return val.to_s         # Couldn't find it... punt.

      end

      def find_selected_option_text( val, collection )

        if collection.is_a?( Hash )
          collection = collection.to_a
        end

        collection.each do |elt|
          if elt.respond_to?( :last ) && !elt.is_a?( String )
            if elt.last == val
              return elt.first.to_s
            end
          else
            if elt == val
              return val.to_s
            end
          end
        end

        # Not found.  Could legitimately be nil... other valid
        # cases are hard to imagine...

        return val.to_s

      end

    end

    # Access-sensitive FormBuilder.  As for the standard FormBuilder,
    # except that all input helpers generate disabled inputs if the
    # current user does not have permission to change the underlying
    # model attribute.
    #
    # (In fact, it's just a subclass of the standard FormBuilder that
    # mixes in Access::Sensitive::FormBuilderDisablingMixin, q.v.)

    class FormBuilder < ActionView::Helpers::FormBuilder
      include FormBuilderMixin
    end

  end

end
