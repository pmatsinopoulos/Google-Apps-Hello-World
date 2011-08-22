class CreateUsers < ActiveRecord::Migration
  def self.up
    create_table :users do |t|
      t.string :email, :null => false
      t.string :open_id, :null => false
      t.boolean :admin_user, :null => false, :default => false

      t.timestamps
    end
  end

  def self.down
    drop_table :users
  end
end
