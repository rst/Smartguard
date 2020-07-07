ActiveRecord::Schema.define(:version => 1) do

  create_table "blog_entries", :force => true do |t|
    t.bigint   "blog_id",       :null => false
    t.text     "entry_txt",     :null => false
    t.timestamp "created_at",    :null => false
    t.timestamp "updated_at",    :null => false
    t.bigint   "owner_id",      :null => false
    t.bigint   "owner_firm_id", :null => false
  end

  add_index "blog_entries", ["owner_firm_id"], :name => "blog_entries_by_firm"
  add_index "blog_entries", ["owner_id"], :name => "blog_entries_by_owner"

  create_table "blogs", :force => true do |t|
    t.string   "name",          :limit => 100, :null => false
    t.timestamp "created_at",                   :null => false
    t.timestamp "updated_at",                   :null => false
    t.bigint   "owner_id",                     :null => false
    t.bigint   "owner_firm_id",                :null => false
  end

  add_index "blogs", ["owner_firm_id"], :name => "blogs_by_firm"
  add_index "blogs", ["owner_id"], :name => "blogs_by_owner"
  add_index "blogs", ["name", "owner_firm_id"], :name => "ix_blogs_by_name_owner_firm", :unique => true

  create_table "entry_comments", :force => true do |t|
    t.bigint   "blog_entry_id"
    t.text     "comment_txt",   :null => false
    t.timestamp "created_at",    :null => false
    t.timestamp "updated_at",    :null => false
    t.bigint   "owner_id",      :null => false
    t.bigint   "owner_firm_id", :null => false
  end

  add_index "entry_comments", ["owner_firm_id"], :name => "entry_comments_by_firm"
  add_index "entry_comments", ["owner_id"], :name => "entry_comments_by_owner"

  create_table "firms", :force => true do |t|
    t.string   "name",                   :limit => 100, :null => false
    t.timestamp "created_at",                            :null => false
    t.timestamp "updated_at",                            :null => false
  end

  create_table "pcheck_log_entries", :force => true do |t|
    t.bigint   "request_log_entry_id",                :null => false
    t.boolean  "success",                             :null => false
    t.string   "model_class",          :limit => 100, :null => false
    t.bigint   "model_id"
    t.string   "privilege",            :limit => 40,  :null => false
    t.bigint   "user_id",                             :null => false
    t.string   "user_name",            :limit => 100, :null => false
    t.timestamp "created_at"
    t.timestamp "updated_at"
  end

  create_table "permissions", :force => true do |t|
    t.bigint   "role_id"
    t.boolean  "is_grant",                            :null => false
    t.boolean  "has_grant_option",                    :null => false
    t.string   "class_name",           :limit => 40,  :null => false
    t.string   "privilege",            :limit => 40,  :null => false
    t.boolean  "target_owned_by_self",                :null => false
    t.bigint   "target_owner_id"
    t.bigint   "target_owner_firm_id"
    t.bigint   "target_id"
    t.string   "target_name",          :limit => 100
    t.timestamp "created_at",                          :null => false
    t.timestamp "updated_at",                          :null => false
  end

  add_index "permissions", ["role_id"], :name => "index_permissions_on_role_id"

  create_table "request_log_entries", :force => true do |t|
    t.timestamp "created_at"
    t.timestamp "updated_at"
    t.bigint   "acting_user_id"
    t.bigint   "user_of_record_id"
    t.string   "acting_user_name"
    t.string   "user_of_record_name"
    t.string   "controller",          :limit => 100, :null => false
    t.string   "action",              :limit => 100, :null => false
    t.string   "http_method",         :limit => 50,  :null => false
    t.string   "status",              :limit => 100, :null => false
    t.string   "model_class",         :limit => 100
    t.bigint   "model_id"
    t.string   "remote_ip",           :limit => 50
  end

  create_table "role_assignments", :force => true do |t|
    t.bigint   "user_id",         :null => false
    t.bigint   "role_id",         :null => false
    t.bigint   "default_user_id"
    t.bigint   "default_firm_id"
    t.timestamp "invalid_after"
    t.timestamp "created_at",      :null => false
    t.timestamp "updated_at",      :null => false
  end

  create_table "roles", :force => true do |t|
    t.string   "name",          :limit => 100, :null => false
    t.timestamp "created_at",                   :null => false
    t.timestamp "updated_at",                   :null => false
    t.bigint   "owner_id",                     :null => false
    t.bigint   "owner_firm_id",                :null => false
    t.bigint   "parent_role_id"
  end

  add_index "roles", ["owner_firm_id"], :name => "roles_by_firm"
  add_index "roles", ["owner_id"], :name => "roles_by_owner"

  create_table "users", :force => true do |t|
    t.string   "name",                     :limit => 100, :null => false
    t.bigint   "owner_firm_id",                           :null => false
    t.timestamp "created_at",                              :null => false
    t.timestamp "updated_at",                              :null => false
  end

  create_table "reports", :force => true do |t|
    t.string   "name",          :limit => 100, :null => false
    t.string   "type",          :limit => 100, :null => false
    t.bigint   "owner_id",                     :null => false
    t.bigint   "owner_firm_id",                :null => false
    t.bigint   "guarded_int"
    t.timestamp "created_at",                   :null => false
    t.timestamp "updated_at",                   :null => false
  end

  create_table "line_items", :force => true do |t|
    t.bigint   "report_id",                    :null => false
    t.bigint   "derived_report_id"
    t.string   "type",          :limit => 100, :null => false
  end

end
