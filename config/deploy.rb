set :application, 'allenlsy.github.com'
set :repo_url, 'git@github.com:allenlsy/allenlsy.github.com.git'

# ask :branch, proc { `git rev-parse --abbrev-ref HEAD`.chomp }

set :deploy_to, "/home/allenlsy/allenlsy.github.com"
set :scm, :git

# server '162.217.248.104'
set :user, 'allenlsy'

set :pty, true

set :bundle_roles, :blog
set :bundle_gemfile, -> { release_path.join('Gemfile') }
set :bundle_dir, -> { shared_path.join('bundle') }
set :bundle_flags, '--deployment --quiet'
set :bundle_without, %w{development test}.join(' ')
set :bundle_binstubs, -> { shared_path.join('bin') }
set :bundle_bins, %w{gem rake ruby}

set :stages, %w(production staging)
set :default_stage, 'production'

# set :rvm_bin_path, "/usr/local/rvm/bin"
set :rvm_roles, [:blog]
set :rvm_type, :user
set :rvm_ruby_version, 'ruby-1.9.3-p547'
set :rvm_path, "~/.rvm"
set :rvm_bin_path, "#{fetch(:rvm_path)}/bin"
set :default_env, { RVM_BIN_PATH: "~/.rvm/bin" }

# set :ssh_options, {
#   forward_agent: true
# } 

# set :format, :pretty
# set :log_level, :debug
# set :pty, true

# set :linked_files, %w{config/database.yml}
# set :linked_dirs, %w{bin log tmp/pids tmp/cache tmp/sockets vendor/bundle public/system}

# set :default_env, { path: "/opt/ruby/bin:$PATH" }
# set :keep_releases, 5


namespace :deploy do
  desc 'Restart application'
  task :restart do
    on roles(:app), in: :sequence, wait: 5 do
      # Your restart mechanism here, for example:
      # execute :touch, release_path.join('tmp/restart.txt')
    end
  end

  desc 'build jekyll '
  task :jekyll_build do
    on roles(:blog) do |host|
      # execute "cd #{fetch(:deploy_to)}/current && bundle && jekyll build"
      within "#{fetch(:deploy_to)}/current" do
        execute :bundle, :install
        execute :bundle, :exec, :jekyll, :build
      end
    end
  end
end

after "deploy:finished", "deploy:jekyll_build"
