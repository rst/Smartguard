require File.dirname(__FILE__) + '/abstract_unit'

# Tests for declare_implied_privilege.
# Use a new class so as not to mess up the other tests by adding implied permissions.

class MyBlog < ActiveRecord::Base

  set_table_name 'blogs'

  include FullTestAccessControl
  owner_attrs_and_validations

  declare_privilege :messwith
  declare_implied_privilege :add_post, :implies => :messwith

  require_privilege :add_post,  :to_associate_as  => 'MyBlogEntry#blog'
  require_privilege :kill_post, :to_dissociate_as => 'MyBlogEntry#blog'

end

class MyBlogEntry < ActiveRecord::Base

  set_table_name 'blog_entries'

  include FullTestAccessControl
  owner_attrs_and_validations

  belongs_to :blog, :class_name => 'MyBlog', :foreign_key => 'blog_id'

  require_eponymous_privilege_to :create, :update

end


class DeclareImpliedPrivilegeTest < Test::Unit::TestCase
  use_all_fixtures

  def setup
    @mertz_blog = MyBlog.create! :name => "FooBlog", :owner => users(:fred),  :owner_firm => firms(:mertz)

    # some users have add_post and some have only messwith
    User.as(users(:universal_grant_guy)) do 
      add_post_role = Role.create! :name => "add_post_role", :owner_firm => firms(:mertz), :owner => User.current
      messwith_role = Role.create! :name => "messwith_role", :owner_firm => firms(:mertz), :owner => User.current
      Permission.create! :role => add_post_role, :is_grant => false, :has_grant_option => false,
	:class_name => "MyBlog",  :target_owner_firm => firms(:mertz),
	:privilege => :add_post, :target_owned_by_self => false
      Permission.create! :role => messwith_role, :is_grant => false, :has_grant_option => false,
	:class_name => "MyBlog",  :target_owner_firm => firms(:mertz),
	:privilege => :messwith, :target_owned_by_self => false
      RoleAssignment.create! :user => users(:fred), :role => add_post_role
      RoleAssignment.create! :user => users(:ethel), :role => messwith_role
    end
  end
  

  def test_can
    with_permission(owner_firm_perm(:add_post, MyBlog, firms(:mertz))) do 
      assert User.current.can?(:messwith, @mertz_blog)
    end
    # post implies messwith but not the other way around
    with_permission(owner_firm_perm(:messwith, MyBlog, firms(:mertz))) do 
      assert User.current.can?(:messwith, @mertz_blog)
      assert !User.current.can?(:add_post, @mertz_blog)
    end
  end

  def test_allows
    perm = blog_post_permission :class_name => 'MyBlog', :privilege => :add_post
    assert perm.allows?(@mertz_blog, :messwith, users(:fred))
    # post implies messwith but not the other way around
    perm = blog_post_permission :class_name => 'MyBlog', :privilege => :messwith
    assert perm.allows?(@mertz_blog, :messwith, users(:fred))
    assert !perm.allows?(@mertz_blog, :add_post, users(:fred))
  end

  def test_users_permitted_sql
    # fred has add_post and should automatically get messwith
    # ethel has only messwith
    users_permitted_sql = MyBlog.users_permitted_sql(:add_post, @mertz_blog)
    add_post_ids = User.connection.select_values(users_permitted_sql)
    users_permitted_sql = MyBlog.users_permitted_sql(:messwith, @mertz_blog)
    messwith_ids = User.connection.select_values(users_permitted_sql)
    assert_equal [users(:fred).id], add_post_ids
    assert_equal [users(:fred).id, users(:ethel).id], messwith_ids 
  end

  def test_where_permits
    mertz_blog_ids = MyBlog.connection.select_values "select id from blogs where owner_firm_id=#{firms(:mertz).id}"
    # fred has both add_post and messwith
    User.as( users(:fred) ) do 
      [:add_post, :messwith].each do |priv|
      where_permits_sql = MyBlog.where_permits(priv) 
	sql = "select id from blogs where #{where_permits_sql}" 
	ids = MyBlog.connection.select_values sql
	assert_equal mertz_blog_ids, ids, "testing priv #{priv}" 
      end
    end
    # ethel has only messwith
    User.as( users(:ethel) ) do 
      where_permits_sql = MyBlog.where_permits(:add_post) 
      sql = "select id from blogs where #{where_permits_sql}" 
      ids = MyBlog.connection.select_values sql
      assert_equal [], ids 
      where_permits_sql = MyBlog.where_permits(:messwith) 
      sql = "select id from blogs where #{where_permits_sql}" 
      ids = MyBlog.connection.select_values sql
      assert_equal mertz_blog_ids, ids 
     end
  end
end

