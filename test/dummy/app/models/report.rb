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
class Report < ActiveRecord::Base

  # Fixture machinery insists on reloading this class, so guard...

  unless method_defined?( :base_method )

    include FullTestAccessControl

    owner_attrs_and_validations
    
    declare_owner_access_control_key 'owner_id'

    require_eponymous_privilege_to :find, :create, :update, :destroy

    require_privilege :update_guarded, :to_set_attribute => :guarded_int
    require_privilege :invoke_base_method, :to_invoke => :base_method
    require_privilege :invoke_derived_method, :to_invoke => :derived_method
    require_privilege :rename, :to_update_attribute => :name

    require_privilege :add_line_item, 
      :to_associate_as  => 'LineItem#report',
      :to_dissociate_as => 'LineItem#report'

    declare_privilege :add_base_line_item

    def base_method; 'base'; end

  end

end
