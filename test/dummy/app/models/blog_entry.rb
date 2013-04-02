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
class BlogEntry < ActiveRecord::Base

  include FullTestAccessControl

  owner_attrs_and_validations

  declare_attribute_block_set_groups FullTestAccessControl::OWNER_ATTRS_GROUP,
    ['blog', 'blog_id']

  belongs_to :blog
  validates_presence_of :blog
  validates_presence_of :entry_txt

  has_many :entry_comments

  require_privilege :change_post, :on_associated => :blog,
    :to_set_attribute => :entry_txt,
    :for_action => [:create, :destroy]

  require_privilege :add_comment, 
    :to_associate_as => "EntryComment#blog_entry"

  require_privilege :kill_comment,
    :to_dissociate_as => "EntryComment#blog_entry"
  
end
