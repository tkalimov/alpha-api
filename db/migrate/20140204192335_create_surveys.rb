class CreateSurveys < ActiveRecord::Migration
  def change
    create_table :surveys do |t|
      t.string :mood

      t.timestamps
    end
  end
end
