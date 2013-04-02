require 'test_helper'

# Tests for declare_implied_privilege.
# Use a new class so as not to mess up the other tests by adding implied permissions.

class MyBlog < ActiveRecord::Base

  self.table_name = 'blogs'

  include FullTestAccessControl
  owner_attrs_and_validations

  declare_privilege :messwith
  declare_implied_privilege :add_post, :implies => :messwith

  require_privilege :add_post,  :to_associate_as  => 'MyBlogEntry#blog'
  require_privilege :kill_post, :to_dissociate_as => 'MyBlogEntry#blog'

end

class MyBlogEntry < ActiveRecord::Base

  self.table_name = 'blog_entries'

  include FullTestAccessControl
  owner_attrs_and_validations

  belongs_to :blog, :class_name => 'MyBlog', :foreign_key => 'blog_id'

  require_eponymous_privilege_to :create, :update

end


class DeclareImpliedPrivilegeTest < ActiveSupport::TestCase
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
    assert_equal [users(:fred).id].sort, add_post_ids.sort
    assert_equal [users(:fred).id, users(:ethel).id].sort, messwith_ids.sort 
  end

  def test_where_permits
    mertz_blog_ids = MyBlog.connection.select_values "select id from blogs where owner_firm_id=#{firms(:mertz).id}"
    # fred has both add_post and messwith
    User.as( users(:fred) ) do 
      [:add_post, :messwith].each do |priv|
      where_permits_sql = MyBlog.where_permits(priv) 
	sql = "select id from blogs where #{where_permits_sql}" 
	ids = MyBlog.connection.select_values sql
	assert_equal mertz_blog_ids.sort, ids.sort, "testing priv #{priv}" 
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
      assert_equal mertz_blog_ids.sort, ids.sort
     end
  end

  def test_force_reload
    User.as( users(:fred) ) do 
      # user starts off with permissions to add_post and (implied) messwith
      assert User.current.can?(:messwith, @mertz_blog) 
      assert User.current.can?(:add_post, @mertz_blog) 

      # remove user's privs
      add_post_role = Role.find_by_name "add_post_role"
      add_post_role_assignment = RoleAssignment.find_by_user_id_and_role_id(User.current.id, add_post_role.id)
      RoleAssignment.delete add_post_role_assignment.id 

      assert (User.current.can?(:messwith, @mertz_blog)) # haven't reloaded yet, still have old perms

      # force reload; user no longer allowed after this
      User.current.permissions(true)  
      assert !(User.current.can?(:messwith, @mertz_blog)) 
      assert !(User.current.can?(:add_post, @mertz_blog)) 
      
      # re-add perms and force reload; user allowed again
      User.as(users(:universal_grant_guy)) do 
	RoleAssignment.create! :user => users(:fred), :role => add_post_role
      end
      User.current.permissions(true)  
      assert User.current.can?(:add_post, @mertz_blog) 
      assert User.current.can?(:messwith, @mertz_blog) 
    end
  end

  def test_implied_grants

    my_grant = Permission.new :target_class => MyBlog, :target => @mertz_blog,
      :privilege => :add_post,
      :is_grant => true, :has_grant_option => false, 
      :target_owned_by_self => false

    my_perm = my_grant.dup

    my_perm.is_grant = false
    assert my_grant.can_grant?( my_perm )
    
    my_perm.privilege = :messwith
    assert my_grant.can_grant?( my_perm )

    my_perm.privilege = :add_post
    my_grant.privilege = :messwith

    assert !my_grant.can_grant?( my_perm )

  end

  def test_can_grant

    myblog_perm = Permission.new :target_class =>MyBlog, :privilege => :messwith, 
                      :is_grant => false, :has_grant_option =>false, :target_owned_by_self => false
    myblogentry_perm = Permission.new :target_class =>MyBlogEntry, :privilege => :create, 
                      :is_grant => false, :has_grant_option =>false, :target_owned_by_self => false
    anyclass_perm = Permission.new :class_name => 'any', :privilege => :create, 
                      :is_grant => false, :has_grant_option =>false, :target_owned_by_self => false
    myblog_ack_perm = Permission.new :class_name => MyBlog, :privilege => :create, 
                      :is_grant => false, :has_grant_option =>false, :target_owned_by_self => false,
                      :target_owner_firm_id => 12

    # test when access control keys match

    # grant(any_class, any_priv)              - always true

                                                                #XXX should foo be allowed here even if not declared on MyBlog?
    single_grant_test( make_a_grant('any', :any), myblog_perm,  :grantable => [:any, :add_post, :messwith, :kill_post, :foo], 
                                                                :not_grantable => [])
    single_grant_test( make_a_grant('any', :any), anyclass_perm,:grantable => [:any, :messwith], 
                                                                :not_grantable => [])
    single_grant_test( make_a_grant('any', :any), myblog_ack_perm, :grantable => [:any, :add_post, :messwith, :kill_post], 
                                                                :not_grantable => [])

    # grant(any_class, named_priv) 
    #     other_priv(any_class, any_priv)     - always false
    #     other_priv(any_class, named_priv)   - false if grant.priv != other_priv.priv
    #     other_priv(named_class, any_priv)   - always false
    #     other_priv(named_class, named_priv) - false unless grant.grantable_privileges_for_class(other_priv.class).include?(other_priv.priv)

    single_grant_test( make_a_grant('any', :add_post), myblog_perm,  :grantable => [:add_post, :messwith], 
                                                                     :not_grantable => [:any, :kill_post, :foo])
    single_grant_test( make_a_grant('any', :messwith), myblog_perm,  :grantable => [:messwith], 
                                                                     :not_grantable =>[:any, :add_post, :kill_post, :foo])
    single_grant_test( make_a_grant('any', :kill_post), myblog_perm, :grantable =>  [:kill_post], 
                                                                     :not_grantable => [:any, :add_post, :messwith, :foo])
    single_grant_test( make_a_grant('any', :add_post), anyclass_perm,:grantable => [:add_post], 
                                                                     # note: add_post implies messwith for the MyBlog class but
                                                                     # we can't assume that's true for 'any' class
                                                                     :not_grantable => [:any, :kill_post, :messwith])
    single_grant_test( make_a_grant('any', :foo), myblog_perm,  :grantable => [:foo],  #XXX should foo be allowed even if not declared on MyBlog?
                                                                :not_grantable => [:any, :kill_post, :messwith, :bar])
                                                         

    # grant(named_class, any_priv)
    #     other_priv(any_class, any_priv)     - always false
    #     other_priv(any_class, named_priv)   - always false
    #     other_priv(named_class, any_priv)   - false unless grant.class == other_priv.class
    #     other_priv(named_class, named_priv) - false unless grant.class == other_priv.class 

                                                                     #XXX should foo be allowed here even if not declared on MyBlog?
    single_grant_test( make_a_grant(MyBlog, :any), myblog_perm,      :grantable => [:any, :add_post, :messwith, :kill_post, :foo], 
                                                                     :not_grantable => [])
    single_grant_test( make_a_grant(MyBlog, :any), myblogentry_perm, :grantable => [], 
                                                                     :not_grantable => [:any, :create, :update, :add_post, :messwith, :kill_post])
    single_grant_test( make_a_grant(MyBlog, :any), anyclass_perm,    :grantable => [], 
                                                                     :not_grantable => [:any, :create, :update, :add_post, :messwith, :kill_post])

    # grant(named_class, named_priv)
    #     other_priv(any_class, any_priv)     - always false
    #     other_priv(any_class, named_priv)   - always false
    #     other_priv(named_class, any_priv)   - always false
    #     other_priv(named_class, named_priv) - false unless ( grant.class == other_priv.class and 
    #                                             grant.grantable_privileges_for_class(other_priv.class).include?(other_priv.priv) )

    single_grant_test( make_a_grant(MyBlog, :add_post), myblog_perm,      :grantable => [:add_post, :messwith], 
                                                                          :not_grantable => [:any, :kill_post, :foo])
    single_grant_test( make_a_grant(MyBlog, :messwith), myblog_perm,      :grantable => [:messwith], 
                                                                          :not_grantable => [:any, :add_post, :kill_post])
    single_grant_test( make_a_grant(MyBlog, :kill_post), myblog_perm,     :grantable => [:kill_post], 
                                                                          :not_grantable => [:any, :add_post, :messwith])
    single_grant_test( make_a_grant(MyBlog, :add_post), myblogentry_perm, :grantable => [], 
                                                                          :not_grantable => [:any, :add_post, :messwith, :kill_post, :create, :update])
    single_grant_test( make_a_grant(MyBlog, :add_post), anyclass_perm,    :grantable => [], 
                                                                          :not_grantable => [:any, :add_post, :messwith, :kill_post, :create, :update])
    single_grant_test( make_a_grant(MyBlog, :foo), myblog_perm,           :grantable => [:foo],  #XXX should foo be allowed even if not declared on MyBlog?
                                                                          :not_grantable => [:any, :kill_post, :messwith, :bar])

    # test the access control keys
    # target_owner_firm_id mismatch
    myblog_ack_perm.target_owner_firm_id = 666
    single_grant_test( make_a_grant('any', :any, :target_owner_firm_id => 100), myblog_ack_perm, 
                                                                          :grantable => [], 
                                                                          :not_grantable => [:add_post, :messwith, :kill_post, :any]) 
    # now matches
    myblog_ack_perm.target_owner_firm_id = 100
    single_grant_test( make_a_grant('any', :any, :target_owner_firm_id => 100), myblog_ack_perm, 
                                                                          :grantable => [:add_post, :messwith, :kill_post, :any], 
                                                                          :not_grantable => [])

  end

  def single_grant_test(g, perm, opts) 

    with_permission_novalidate(g) do
      opts[:grantable].each do |p|
        perm.privilege = p
        assert g.can_grant?(perm), "#{g.inspect} should be able to grant #{p}"
      end
      opts[:not_grantable].each do |p|
        perm.privilege = p
        assert !g.can_grant?(perm), "#{g.inspect} should not be able to grant #{p}"
      end
    end
  end

  def test_grantable_privileges_for_class
  # these are the declared privs for our test classes
  myblog_all_declared = [:any, :add_post, :messwith, :kill_post, :permit_individually, :reassign].sort_by(&:to_s)
  myblogentry_all_declared = [:any, :create, :update, :permit_individually, :reassign].sort_by(&:to_s)

  # grant(any_class, any_priv)      - return all declared privs of klass 
    g = make_a_grant('any', :any)
    assert_equal myblog_all_declared, g.grantable_privileges_for_class(MyBlog).sort_by(&:to_s)
    assert_equal myblogentry_all_declared, g.grantable_privileges_for_class(MyBlogEntry).sort_by(&:to_s)
  # grant(any_class, named_priv)    - return named_priv + anything it implies
    g = make_a_grant('any', :messwith)
    assert_equal [:messwith], g.grantable_privileges_for_class(MyBlog).sort_by(&:to_s)
    g = make_a_grant('any', :add_post)
    assert_equal [:add_post, :messwith], g.grantable_privileges_for_class(MyBlog).sort_by(&:to_s)
    #XXX should this be [] since MyBlogEntry does not declare the :add_post privilege?
    assert_equal [:add_post], g.grantable_privileges_for_class(MyBlogEntry).sort_by(&:to_s)
  # grant(named_class, any_priv)    - if named_class==klass return all declared privs of klass else return []
    g = make_a_grant(MyBlog, :any)
    assert_equal myblog_all_declared, g.grantable_privileges_for_class(MyBlog).sort_by(&:to_s)
    assert_equal [], g.grantable_privileges_for_class(MyBlogEntry).sort_by(&:to_s)
  # grant(named_class, named_priv)  - if named_class==klass return (named_priv + anything it implies) else return []
    g = make_a_grant(MyBlog, :add_post)
    assert_equal [:add_post, :messwith], g.grantable_privileges_for_class(MyBlog).sort_by(&:to_s)
    assert_equal [], g.grantable_privileges_for_class(MyBlogEntry).sort_by(&:to_s)      # wrong class - return nothing
    g = make_a_grant(MyBlog, :messwith)
    assert_equal [:messwith], g.grantable_privileges_for_class(MyBlog).sort_by(&:to_s)
    g = make_a_grant(MyBlog, :kill_post)
    assert_equal [:kill_post], g.grantable_privileges_for_class(MyBlog).sort_by(&:to_s)
    assert_equal [], g.grantable_privileges_for_class(MyBlogEntry).sort_by(&:to_s)      # wrong class - return nothing
  end

  def test_grantable_privileges

    my_grant = Permission.new :target_class => MyBlog, :target => @mertz_blog,
      :privilege => :messwith,
      :is_grant => true, :has_grant_option => false, 
      :target_owned_by_self => false

    assert_equal [:messwith], my_grant.grantable_privileges

    my_grant.privilege = :add_post
    assert_equal [:add_post, :messwith], 
                 my_grant.grantable_privileges.sort_by(&:to_s)

    my_grant.privilege = :any
    assert_equal ([:any] + MyBlog.declared_privileges).sort_by(&:to_s),
                 my_grant.grantable_privileges.sort_by(&:to_s)

  end

  def test_alternate_privileges_for_edit

    messwith_grant = Permission.new :target_class => MyBlog, 
      :target => @mertz_blog,
      :privilege => :messwith,
      :is_grant => true, :has_grant_option => false, 
      :target_owned_by_self => false

    add_post_grant = messwith_grant.dup
    add_post_grant.privilege = :add_post

    simple_perm = messwith_grant.dup
    simple_perm.is_grant = false

    # if the user can only grant :messwith they should not see the alternate priv :add_post
    with_permission( messwith_grant ) do
      assert_equal [:messwith], simple_perm.alternate_privileges_for_edit
    end

    # if the user can grant :add_post they should see both alternate privs 
    [:messwith, :add_post].each do |priv|

      simple_perm.privilege = priv

      with_permission( add_post_grant ) do
        assert_equal [:add_post, :messwith], 
          simple_perm.alternate_privileges_for_edit.sort_by(&:to_s)
      end
    end

    # kill_post does not imply and is not implied by anything
    # the only alternates returned should be the kill_post itself provided the user can grant it
    kill_post_perm = messwith_grant.dup
    kill_post_perm.privilege = :kill_post
    kill_post_perm.is_grant = false
    kill_post_grant = messwith_grant.dup
    kill_post_grant.privilege = :kill_post
    with_permission( kill_post_grant ) do
      assert_equal [:kill_post], kill_post_perm.alternate_privileges_for_edit.sort_by(&:to_s)
    end
    with_permission( add_post_grant ) do  # don't have permission -- empty result
      assert_equal [], kill_post_perm.alternate_privileges_for_edit.sort_by(&:to_s)
    end

    # test the case where the user has the powerful any privilege grant
    # the only alternates to be returned are privs that imply or are implied by this priv
    any_myblog_grant = Permission.new :target_class => MyBlog, 
      :privilege => :any,
      :is_grant => true, :has_grant_option => false, 
      :target_owned_by_self => false
    any_any_grant = Permission.new :class_name => "any", 
      :privilege => :any,
      :is_grant => true, :has_grant_option => false, 
      :target_owned_by_self => false
    addpost_any_grant = Permission.new :class_name => "any", 
      :privilege => :add_post,
      :is_grant => true, :has_grant_option => false, 
      :target_owned_by_self => false
    [any_myblog_grant, any_any_grant].each do |g|
      with_permission_novalidate(g) do 
        assert_equal [:add_post, :messwith], simple_perm.alternate_privileges_for_edit.sort_by(&:to_s)
        assert_equal [:kill_post], kill_post_perm.alternate_privileges_for_edit.sort_by(&:to_s)
      end
    end

    [addpost_any_grant].each do |g|
      with_permission_novalidate(g) do 
        assert_equal [:add_post, :messwith], simple_perm.alternate_privileges_for_edit.sort_by(&:to_s)
        assert_equal [], kill_post_perm.alternate_privileges_for_edit.sort_by(&:to_s)
      end
    end

  end


  # hack to allow perms with class_name="any" (these would ordinarily fail validation)
  def with_permission_novalidate( *perms )
    with_test_role_for_unprivileged_guy( :no_grants ) do |user, role|
      User.as( users(:universal_grant_guy) ) do
        perms.each do |perm|
          perm = perm.dup
          perm.role = role
          perm.save(:validate => false)
        end
      end
      user.permissions :force_reload
      yield
    end
  end

  def make_a_grant(klass, privilege, attrs={})
    default_attrs = {:privilege => privilege, :is_grant => true, :has_grant_option => false, :target_owned_by_self => false}
    if klass.is_a? Class
      default_attrs[:target_class] = klass
    else 
      default_attrs[:class_name] = klass
    end
      Permission.new default_attrs.merge(attrs)
  end

end

