class CreatePermissions < ActiveRecord::Migration
  def self.up
    create_table :permissions do |t|
      t.integer :role_id

      t.boolean :is_grant,             :null => false, :default => false
      t.boolean :has_grant_option,     :null => false, :default => false

      t.string :class_name, :limit => 40, :null => false
      t.string :privilege,  :limit => 40, :null => false

      t.boolean :target_owned_by_self, :null => false, :default => false
      t.integer :target_owner_id
      t.integer :target_id
      t.string  :target_name

      t.timestamps
    end

    add_index :permissions, :role_id
  end

  def self.down
    drop_table :permissions
  end
end
