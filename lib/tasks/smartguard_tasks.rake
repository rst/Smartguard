# Technique borrowed from Alistair Israel;
# http://alistairisrael.wordpress.com/2007/07/27/bootstrapping-your-database-with-ordered-fixtures/

require 'etc'

namespace :db do
  desc "Load bootstrap fixtures (from db/sg_bootstrap) into "+
       "the current environment's database." 
  task :sg_bootstrap => :environment do

    require 'active_record/fixtures'
    dir = RAILS_ROOT + '/db/sg_bootstrap/'
    files = Dir.glob(dir + '*.yml').sort

    connection = ActiveRecord::Base.connection

    fixtures = files.collect { |file|
      file_basename = File.basename(file, '.*')
      table_name = file_basename.gsub( /^[0-9]+_/, '' )
      Fixtures.new(connection, table_name, nil, dir + file_basename)
    }

    connection.transaction(Thread.current['open_transactions'] == 0) do

      fixtures.reverse.each { |fixture| fixture.delete_existing_fixtures }
      fixtures.each { |fixture| fixture.insert_fixtures }

      if connection.respond_to?(:reset_pk_sequence!)
        files.each do |file|
          file_basename = File.basename(file, '.*')
          table_name = file_basename.gsub( /^[0-9]+_/, '' )
          connection.reset_pk_sequence!(table_name)
        end
      end
    end

  end
end
