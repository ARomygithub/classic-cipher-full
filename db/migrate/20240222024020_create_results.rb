class CreateResults < ActiveRecord::Migration[7.1]
  def change
    create_table :results do |t|
      t.string :plain
      t.string :base64

      t.timestamps
    end
  end
end
