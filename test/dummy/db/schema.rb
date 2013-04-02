ActiveRecord::Schema.define(:version => 1) do

  create_table "blog_entries", :force => true do |t|
    t.integer  "blog_id",       :null => false
    t.text     "entry_txt",     :null => false
    t.datetime "created_at",    :null => false
    t.datetime "updated_at",    :null => false
    t.integer  "owner_id",      :null => false
    t.integer  "owner_firm_id", :null => false
  end

  add_index "blog_entries", ["owner_firm_id"], :name => "blog_entries_by_firm"
  add_index "blog_entries", ["owner_id"], :name => "blog_entries_by_owner"

  create_table "blogs", :force => true do |t|
    t.string   "name",          :limit => 100, :null => false
    t.datetime "created_at",                   :null => false
    t.datetime "updated_at",                   :null => false
    t.integer  "owner_id",                     :null => false
    t.integer  "owner_firm_id",                :null => false
  end

  add_index "blogs", ["owner_firm_id"], :name => "blogs_by_firm"
  add_index "blogs", ["owner_id"], :name => "blogs_by_owner"
  add_index "blogs", ["name", "owner_firm_id"], :name => "ix_blogs_by_name_owner_firm", :unique => true

  create_table "entry_comments", :force => true do |t|
    t.integer  "blog_entry_id"
    t.text     "comment_txt",   :null => false
    t.datetime "created_at",    :null => false
    t.datetime "updated_at",    :null => false
    t.integer  "owner_id",      :null => false
    t.integer  "owner_firm_id", :null => false
  end

  add_index "entry_comments", ["owner_firm_id"], :name => "entry_comments_by_firm"
  add_index "entry_comments", ["owner_id"], :name => "entry_comments_by_owner"

  create_table "firms", :force => true do |t|
    t.string   "name",                   :limit => 100, :null => false
    t.datetime "created_at",                            :null => false
    t.datetime "updated_at",                            :null => false
  end

  create_table "pcheck_log_entries", :force => true do |t|
    t.integer  "request_log_entry_id",                :null => false
    t.boolean  "success",                             :null => false
    t.string   "model_class",          :limit => 100, :null => false
    t.integer  "model_id"
    t.string   "privilege",            :limit => 40,  :null => false
    t.integer  "user_id",                             :null => false
    t.string   "user_name",            :limit => 100, :null => false
    t.datetime "created_at"
    t.datetime "updated_at"
  end

  create_table "permissions", :force => true do |t|
    t.integer  "role_id"
    t.boolean  "is_grant",                            :null => false
    t.boolean  "has_grant_option",                    :null => false
    t.string   "class_name",           :limit => 40,  :null => false
    t.string   "privilege",            :limit => 40,  :null => false
    t.boolean  "target_owned_by_self",                :null => false
    t.integer  "target_owner_id"
    t.integer  "target_owner_firm_id"
    t.integer  "target_id"
    t.string   "target_name",          :limit => 100
    t.datetime "created_at",                          :null => false
    t.datetime "updated_at",                          :null => false
  end

  add_index "permissions", ["role_id"], :name => "index_permissions_on_role_id"

  create_table "request_log_entries", :force => true do |t|
    t.datetime "created_at"
    t.datetime "updated_at"
    t.integer  "acting_user_id"
    t.integer  "user_of_record_id"
    t.string   "acting_user_name"
    t.string   "user_of_record_name"
    t.string   "controller",          :limit => 100, :null => false
    t.string   "action",              :limit => 100, :null => false
    t.string   "http_method",         :limit => 50,  :null => false
    t.string   "status",              :limit => 100, :null => false
    t.string   "model_class",         :limit => 100
    t.integer  "model_id"
    t.string   "remote_ip",           :limit => 50
  end

  create_table "role_assignments", :force => true do |t|
    t.integer  "user_id",         :null => false
    t.integer  "role_id",         :null => false
    t.integer  "default_user_id"
    t.integer  "default_firm_id"
    t.datetime "invalid_after"
    t.datetime "created_at",      :null => false
    t.datetime "updated_at",      :null => false
  end

  create_table "roles", :force => true do |t|
    t.string   "name",          :limit => 100, :null => false
    t.datetime "created_at",                   :null => false
    t.datetime "updated_at",                   :null => false
    t.integer  "owner_id",                     :null => false
    t.integer  "owner_firm_id",                :null => false
    t.integer  "parent_role_id"
  end

  add_index "roles", ["owner_firm_id"], :name => "roles_by_firm"
  add_index "roles", ["owner_id"], :name => "roles_by_owner"

  create_table "users", :force => true do |t|
    t.string   "name",                     :limit => 100, :null => false
    t.integer  "owner_firm_id",                           :null => false
    t.datetime "created_at",                              :null => false
    t.datetime "updated_at",                              :null => false
  end

  create_table "reports", :force => true do |t|
    t.string   "name",          :limit => 100, :null => false
    t.string   "type",          :limit => 100, :null => false
    t.integer  "owner_id",                     :null => false
    t.integer  "owner_firm_id",                :null => false
    t.integer  "guarded_int"
    t.datetime "created_at",                   :null => false
    t.datetime "updated_at",                   :null => false
  end

  create_table "line_items", :force => true do |t|
    t.integer  "report_id",                    :null => false
    t.integer  "derived_report_id"
    t.string   "type",          :limit => 100, :null => false
  end

end