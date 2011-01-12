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

class AcPhonyBlog < ActiveRecord::Base

  set_table_name 'blogs'

  include Access::Controlled

  attr_accessor :unguarded, :guarded_date, :guarded_nil,
    :guarded_number, :guarded_bool_false

  require_privilege :change_guarded, 
    :to_set_attribute => [:name, :guarded_date, :guarded_number,
                          :guarded_nil, :guarded_bool_false ]

end

# Collection elements for collection_select

class Wombat
  attr_accessor :id, :name
  def initialize( id, name )
    self.id = id
    self.name = name
  end
end

class AcsFormBuilderTest < ActionController::TestCase

  CHECKMARK = Access::Sensitive::FormBuilderMixin::CHECKMARK

  include ActionView::Helpers::TagHelper
  include ActionView::Helpers::FormHelper
  include ActionView::Helpers::FormOptionsHelper
  include ActionView::Helpers::DateHelper

  use_all_fixtures

  def test_everything_wrapped

    # Identify methods that actually name tag helpers ---
    # slightly tricky, since they keep adding more.
    #
    # The rule we use here is that it must be a method
    # defined on FormBuilder itself, which is not a setter,
    # nor an accessor on any attribute that has a setter.
    #
    # It works.  For the moment.

    fbuilder = ActionView::Helpers::FormBuilder
    meth_names = 
      fbuilder.instance_methods - fbuilder.superclass.instance_methods
    setters = meth_names.grep( /=$/ )
    attrs   = setters.collect &:chop
    helpers = meth_names - setters - attrs

    # Now check that the list of things we wrap (or *should*) covers it all.

    helpers-=Access::Sensitive::FormBuilderMixin::SIMPLE_FORM_HELPERS
    helpers-=Access::Sensitive::FormBuilderMixin::OTHER_FORM_HELPERS
    helpers-=Access::Sensitive::FormBuilderMixin::JUNK_METHODS

    assert_equal [], helpers
    
  end

  def test_text_field

    # The code paths for file fields, password fields, and hidden fields
    # are the same as here, so this test is assumed to cover those as well.

    blog = test_blog

    with_test_role_for_unprivileged_guy do |user, role|

      # Text non-permitted display test.  
      # Done first, since subsequent tests will change privileges

      fields_for :blog, blog,
                 :builder => Access::Sensitive::FormBuilder,
                 :if_not_permitted => :present_text do |f|
        assert_equal "fred the blog", f.text_field( :name )
      end

      # Disabled-input test

      fields_for :blog, blog, :builder => Access::Sensitive::FormBuilder do |f|

        # First, see what it does with no privileges...

        assert_dom_equal( trim(<<-EOD), f.text_field( :name ) )
           <input disabled="disabled" id="disabled_blog_name" 
                  value="fred the blog"
                  name="disabled_blog[name]" size="30" type="text" />
        EOD

        assert_dom_equal( trim(<<-EOD), f.text_field( :name, :size => 23 ) )
           <input disabled="disabled" id="disabled_blog_name" 
                  value="fred the blog"
                  name="disabled_blog[name]" size="23" type="text" />
        EOD

        # Now, with privileges:

        role.permissions << one_object_perm( :change_guarded, blog )
        user.permissions :force_reload
      
        assert_dom_equal( trim(<<-EOD), f.text_field( :name ) )
           <input id="blog_name" name="blog[name]" size="30" type="text" 
                  value="fred the blog" />
        EOD

        assert_dom_equal( trim(<<-EOD), f.text_field( :name, :size => 23 ) )
           <input id="blog_name" name="blog[name]" size="23" type="text" 
                  value="fred the blog" />
        EOD

        # And lastly, on an attr with no privilege declarations
        # or requirements (just once, as the macro-generated test logic 
        # is the same for all other helpers)

        assert_dom_equal( trim(<<-EOD), f.text_field( :unguarded, :size=>23 ) )
           <input id="blog_unguarded" name="blog[unguarded]" 
                  size="23" type="text" />
        EOD

      end

    end
    
  end

  def test_text_area

    blog = test_blog

    with_test_role_for_unprivileged_guy do |user, role|

      # Text non-permitted display test.  
      # Done first, since subsequent tests will change privileges

      fields_for :blog, blog,
                 :builder => Access::Sensitive::FormBuilder,
                 :if_not_permitted => :present_text do |f|
        assert_equal "fred the blog", f.text_area( :name )
      end

      # Disabled-input test

      fields_for :blog, blog, :builder => Access::Sensitive::FormBuilder do |f|

        # First, see what it does with no privileges...

        assert_dom_equal( trim(<<-EOD), f.text_area( :name ) )
           <textarea disabled="disabled" id="disabled_blog_name" 
                  name="disabled_blog[name]" rows="20" cols="40" 
            >fred the blog</textarea>
        EOD

        assert_dom_equal( trim(<<-EOD), f.text_area( :name, :rows => 7 ) )
           <textarea disabled="disabled" id="disabled_blog_name" 
                  name="disabled_blog[name]" rows="7" cols="40" 
            >fred the blog</textarea>
        EOD

        # Now, with privileges:

        role.permissions << one_object_perm( :change_guarded, blog )
        user.permissions :force_reload
      
        assert_dom_equal( trim(<<-EOD), f.text_area( :name ) )
           <textarea id="blog_name" name="blog[name]" rows="20" cols="40" 
            >fred the blog</textarea>
        EOD

        assert_dom_equal( trim(<<-EOD), f.text_area( :name, :rows => 7 ) )
           <textarea id="blog_name" name="blog[name]" rows="7" cols="40" 
            >fred the blog</textarea>
        EOD

      end

    end
    
  end

  def test_date_select

    # There's enough commonality in the internal code that
    # this should also cover for time_select and datetime_select...

    blog = test_blog

    with_test_role_for_unprivileged_guy do |user, role|

      # Text non-permitted display test.  
      # Done first, since subsequent tests will change privileges.
      # Note that the text produced here is what comes from to_s,
      # which is unaware of and will not respect any :omit_foo
      # keyword args, etc.  SUBOPTIMAL.

      fields_for :blog, blog,
                 :builder => Access::Sensitive::FormBuilder,
                 :if_not_permitted => :present_text do |f|
        assert_equal Date.civil(1945,5,8).to_s, f.text_field( :guarded_date )
        with_attr( blog, :guarded_date, nil ) do
          assert_equal '', f.text_field( :guarded_date )
        end
      end

      # Disabled-input test

      fields_for :blog, blog, :builder => Access::Sensitive::FormBuilder do |f|

        select_lines = f.date_select( :guarded_date ).split("\n")
        assert( select_lines.detect do |line|
          /select/ === line && 
            /id="disabled_blog_guarded_date_1i"/ === line &&
            /disabled="disabled"/ === line
        end)
        assert( select_lines.detect do |line|
          /option/ === line && 
            /value="1945"/ === line &&
            /selected="selected"/ === line
        end)

        role.permissions << one_object_perm( :change_guarded, blog )
        user.permissions :force_reload

        select_lines = f.date_select( :guarded_date ).split("\n")
        assert( select_lines.detect do |line|
          /select/ === line && 
            /id="blog_guarded_date_1i"/ === line &&
            !(/disabled="disabled"/ === line)
        end)
        assert( select_lines.detect do |line|
          /option/ === line && 
            /value="1945"/ === line &&
            /selected="selected"/ === line
        end)


      end

    end

  end

  def test_check_box

    blog = test_blog

    with_test_role_for_unprivileged_guy do |user, role|

      # Text non-permitted display test.  
      # Done first, since subsequent tests will change privileges

      fields_for :blog, blog,
                 :builder => Access::Sensitive::FormBuilder,
                 :if_not_permitted => :present_text do |f|

        with_attr( blog, :guarded_number, 1 ) do
          assert_equal CHECKMARK, f.check_box( :guarded_number )
        end
        with_attr( blog, :guarded_number, 0 ) do
          assert_equal '', f.check_box( :guarded_number, {}, true, false )
        end

        with_attr( blog, :guarded_number, "1" ) do
          assert_equal CHECKMARK, f.check_box( :guarded_number )
        end
        with_attr( blog, :guarded_number, "0" ) do
          assert_equal '', f.check_box( :guarded_number, {}, true, false )
        end

        assert_equal '', f.check_box( :guarded_bool_false )
        with_attr( blog, :guarded_bool_false, true ) do
          assert_equal CHECKMARK,f.check_box(:guarded_bool_false,{},true,false)
        end

      end

      # Disabled-input test

      fields_for :blog, blog, :builder => Access::Sensitive::FormBuilder do |f|

        # There's some weirdness with the value in a hidden input here...
        # but since it's the disabled case, the value is ignored and
        # irrelevant...

        check_html = f.check_box( :guarded_number )
        check_html = check_html.gsub( /<input name="disabled.*>/, '' )

        assert_dom_equal( trim(<<-EOD), check_html )
            <input checked="checked" disabled="disabled" 
                   id="disabled_blog_guarded_number" 
                   name="disabled_blog[guarded_number]" type="checkbox" 
                   value="1"
             />
        EOD
        cbox_txt = f.check_box( :guarded_bool_false, {}, true, false )
        assert_dom_equal( trim(<<-EOD), cbox_txt)
           <input disabled="disabled" id="disabled_blog_guarded_bool_false" 
                  name="disabled_blog[guarded_bool_false]" type="checkbox" 
                  value="true" 
            /><input name="disabled_blog[guarded_bool_false]" 
                     type="hidden" value="false"/>
        EOD

        role.permissions << one_object_perm( :change_guarded, blog )
        user.permissions :force_reload

        assert_dom_equal( trim(<<-EOD), f.check_box( :guarded_number ))
            <input checked="checked" id="blog_guarded_number" 
                   name="blog[guarded_number]" type="checkbox" 
                   value="1"
             /><input name="blog[guarded_number]" type="hidden" value="0" />
        EOD
        cbox_txt = f.check_box( :guarded_bool_false, {}, true, false )
        assert_dom_equal( trim(<<-EOD), cbox_txt)
           <input id="blog_guarded_bool_false" name="blog[guarded_bool_false]" 
                  type="checkbox" value="true" 
            /><input name="blog[guarded_bool_false]" 
                     type="hidden" value="false"/>
        EOD

      end

    end

  end

  def test_radio_button

    blog = test_blog

    with_test_role_for_unprivileged_guy do |user, role|

      # Text non-permitted display test.  
      # Done first, since subsequent tests will change privileges

      fields_for :blog, blog,
                 :builder => Access::Sensitive::FormBuilder,
                 :if_not_permitted => :present_text do |f|
        assert_equal '',        f.radio_button( :guarded_number, 2 )
        assert_equal CHECKMARK, f.radio_button( :guarded_number, 3 )
      end

      # Disabled-input test

      fields_for :blog, blog, :builder => Access::Sensitive::FormBuilder do |f|

        assert_dom_equal( trim(<<-EOD), f.radio_button( :guarded_number, 2 ))
            <input disabled="disabled" id="disabled_blog_guarded_number_2" 
                   name="disabled_blog[guarded_number]" 
                   type="radio" value="2" />
        EOD
        assert_dom_equal( trim(<<-EOD), f.radio_button( :guarded_number, 3 ))
            <input disabled="disabled" id="disabled_blog_guarded_number_3" 
                   name="disabled_blog[guarded_number]" 
                   type="radio" value="3" checked="checked" />
        EOD

        role.permissions << one_object_perm( :change_guarded, blog )
        user.permissions :force_reload

        assert_dom_equal( trim(<<-EOD), f.radio_button( :guarded_number, 2 ))
            <input id="blog_guarded_number_2" name="blog[guarded_number]" 
                   type="radio" value="2" />
        EOD
        assert_dom_equal( trim(<<-EOD), f.radio_button( :guarded_number, 3 ))
            <input id="blog_guarded_number_3" name="blog[guarded_number]" 
                   type="radio" value="3" checked="checked" />
        EOD

      end

    end

  end

  def test_select

    blog = test_blog

    with_test_role_for_unprivileged_guy do |user, role|

      # Text non-permitted display test.  
      # Done first, since subsequent tests will change privileges

      fields_for :blog, blog,
                 :builder => Access::Sensitive::FormBuilder,
                 :if_not_permitted => :present_text do |f|
        assert_equal 'fred', f.select(:guarded_number,[['fred',3],['ethel',4]])
        assert_equal '3', f.select(:guarded_number, [3,4])
        assert_equal 'fred', f.select(:guarded_number,
                                      { :fred => 3, :ethel => 4 })
      end

      # Disabled-input test

      fields_for :blog, blog, :builder => Access::Sensitive::FormBuilder do |f|

        select_txt = f.select( :guarded_number, [['fred',3],['ethel',4]] )
        assert_dom_equal( trim(<<-EOD), select_txt )
            <select disabled="disabled" 
                    id="disabled_blog_guarded_number" 
                    name="disabled_blog[guarded_number]"
                ><option value="3" selected="selected">fred</option>
                 <option value="4">ethel</option></select>
        EOD

        role.permissions << one_object_perm( :change_guarded, blog )
        user.permissions :force_reload

        select_txt = f.select( :guarded_number, [['fred',3],['ethel',4]] )
        assert_dom_equal( trim(<<-EOD), select_txt )
            <select id="blog_guarded_number" name="blog[guarded_number]"
                ><option value="3" selected="selected">fred</option>
                 <option value="4">ethel</option></select>
        EOD

      end

    end

  end

  def test_collection_select

    blog = test_blog
    wombats = [ Wombat.new(2, "Claude"), 
                Wombat.new(3, "James"),
                Wombat.new(4, "Billingsley") ]

    with_test_role_for_unprivileged_guy do |user, role|

      # Text non-permitted display test.  
      # Done first, since subsequent tests will change privileges

      fields_for :blog, blog,
                 :builder => Access::Sensitive::FormBuilder,
                 :if_not_permitted => :present_text do |f|
        assert_equal 'James', 
          f.collection_select( :guarded_number, wombats, :id, :name )
      end

      # Now the disabled-elt test

      fields_for :blog, blog, :builder => Access::Sensitive::FormBuilder do |f|

        select_txt = f.collection_select(:guarded_number, wombats, :id, :name)
        assert_dom_equal( trim(<<-EOD), select_txt )
           <select disabled="disabled" id="disabled_blog_guarded_number" 
                   name="disabled_blog[guarded_number]"
             ><option value="2">Claude</option>
              <option value="3" selected="selected">James</option>
              <option value="4">Billingsley</option></select>
        EOD

        role.permissions << one_object_perm( :change_guarded, blog )
        user.permissions :force_reload

        select_txt = f.collection_select(:guarded_number, wombats, :id, :name)
        assert_dom_equal( trim(<<-EOD), select_txt )
           <select id="blog_guarded_number" name="blog[guarded_number]"
             ><option value="2">Claude</option>
              <option value="3" selected="selected">James</option>
              <option value="4">Billingsley</option></select>
        EOD

      end

    end

  end

  def test_precooked_selects

    blog = test_blog

    # country_select used to be here, till scrapped with Rails 2.2

    [:time_zone_select].each do |selector|

      with_test_role_for_unprivileged_guy do |user, role|

        fields_for :blog, blog, :builder=>Access::Sensitive::FormBuilder do |f|

          txt = f.send selector, :guarded_nil
          first = txt.split("\n").first
          assert_match    /<select/,             first
          assert_match    /disabled="disabled"/, first
          assert_match    /name="disabled_blog/, first

          role.permissions << one_object_perm( :change_guarded, blog )
          user.permissions :force_reload

          txt = f.send selector, :guarded_nil
          first = txt.split("\n").first
          assert_match    /<select/,                 first
          assert_match    /name="blog\[guarded_nil/, first
          assert_no_match /disabled="disabled"/,     first

        end
      end
    end
  end

  def skeleton_test

    blog = test_blog

    with_test_role_for_unprivileged_guy do |user, role|

      fields_for :blog, blog, :builder => Access::Sensitive::FormBuilder do |f|

        role.permissions << one_object_perm( :change_guarded, blog )
        user.permissions :force_reload

      end

    end

  end

  private

  def trim( s )
    s = s.gsub(/^\s*/, '')
    s = s.gsub(/\s*$/, '')
    s
  end

  def test_blog

    blog = AcPhonyBlog.new

    assert_requires( one_object_perm( :change_guarded, blog ) ) do
      blog.attributes = {
        :name => "fred the blog",
        :guarded_nil => nil,
        :guarded_bool_false => false,
        :guarded_number => 3,
        :guarded_date => Date.civil(1945, 5, 8) # v-e day
      }
    end

    blog

  end

  def with_attr( object, attr, val )

    # Use some voodoo to bypass permission checks.
    # *Really* locking down the model objects against malicious
    # programmers would require disabling this, and much similar stuff...

    ivar = '@' + attr.to_s
    old_val = object.instance_variable_get ivar
    begin 
      object.instance_variable_set ivar, val
      yield
    ensure
      object.instance_variable_set ivar, old_val
    end
  end

end
