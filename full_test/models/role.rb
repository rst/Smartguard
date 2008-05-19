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

class Role < ActiveRecord::Base

  include FullTestAccessControl
  include SmartguardBasicRole

  puts "role ack groups #{attribute_block_set_groups.inspect}"

  owner_attrs_and_validations :default_from_current_user => true

  require_privilege :assign, :to_associate_as  => 'RoleAssignment#role'
  require_privilege :edit,   :to_associate_as  => 'Permission#role',
                             :to_dissociate_as => 'Permission#role'

  require_eponymous_privilege_to :create, :destroy

  validates_length_of     :name, :within => 3..100
  validates_uniqueness_of :name, :scope => :owner_firm_id

end
