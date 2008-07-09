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
class Permission < ActiveRecord::Base

  include Access::Controlled
  include SmartguardBasicPermission

  def description

    desc = ''

    if is_grant? && has_grant_option?
      desc += 'grant permission (with grant option) to '
    elsif is_grant?
      desc += 'grant permission to '
    end

    if privilege == :any
      desc += 'take any action on '
    else
      desc += privilege.to_s + ' '
    end

    if target_paid == true
      desc += 'paid '
    elsif target_paid == false
      desc += 'unpaid '
    end

    if class_name == 'any'
      desc += 'anything '
    elsif target_name != nil
      desc += class_name.downcase + ' '
    else
      desc += class_name.downcase.pluralize + ' '
    end

    restrictions = []
    restrictions << "owned by grantee" if target_owned_by_self
    restrictions << "owned by #{target_owner.name}" unless target_owner.nil?
    restrictions << "of firm #{target_owner_firm.name}" unless 
                                                        target_owner_firm.nil?
    restrictions << '"' + target_name + '"' unless target_name.nil?

    desc + restrictions.join(', ')

  end

  # Sort key; may be helpful for presentation...

  def ui_sort_order
    (self.is_grant? ? 'T' : 'F') + self.class_name + ' ' + self.privilege.to_s
  end

end
