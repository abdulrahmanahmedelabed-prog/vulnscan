namespace :cleanup do
  task :uploads, [:days] => :environment do |t, args|
    system("find /srv/uploads -mtime +#{args[:days]} -delete")
  end
end
