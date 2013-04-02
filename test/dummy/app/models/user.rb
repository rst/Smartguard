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

class User < ActiveRecord::Base

  include FullTestAccessControl
  include SmartguardBasicUser

  declare_access_control_keys 'id', 'owner_firm_id'

  require_eponymous_privilege_to :create

  require_privilege :administer,
    :to_associate_as  => 'RoleAssignment#user',
    :to_dissociate_as => 'RoleAssignment#user'

  require_privilege :rename, 
    :to_update_attribute => [:name, :full_name, :search_name]

  belongs_to :firm, :class_name => 'Firm', 
                    :foreign_key => :owner_firm_id

  validates_presence_of :name
  validates_length_of :name, :minimum => 3

  validates_presence_of   :firm

end
