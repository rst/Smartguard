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
module SmartguardBasicRoleAssignment

  module ClassMethods

    def current_sql_condition
      @current_sql_condition ||=
        (if self.connection.class.name =~ /Oracle/ then
           "(role_assignments.invalid_after is null
             or role_assignments.invalid_after > sysdate)"
         else
           "(role_assignments.invalid_after is null
             or role_assignments.invalid_after > now())"
         end
         )
    end

  end

  def self.included( klass )

    klass.belongs_to :user
    klass.belongs_to :role

    klass.validates_presence_of :user
    klass.validates_presence_of :role

    klass.never_permit_anyone :to_update_attribute => [:user_id, :role_id]

    klass.extend ClassMethods

  end

end
