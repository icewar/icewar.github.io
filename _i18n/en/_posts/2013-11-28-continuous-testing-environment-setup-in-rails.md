---
layout: post
title: " Super Fast Continuous Testing in Rails"
subtitle: "An intruduction to set up a good testing environment in Ruby on Rails 4"
cover_image: 
excerpt: "My understanding of continuous testing is that, there is a testing tool in the background, which while developing and modifying code, it will continuously notify you the broken of correct code. I usually set up the testing environment using `RSpec`, `Spork` and `Guard`. The setup process may easily go wrong. Thus I made a note of the process."
category: 
tags: [testing, rails, ci, rspec, ruby]
thumbnail: "http://www.continuoustests.com/images/logo.png"
---

![](http://www.continuoustests.com/images/logo.png)

> Before reading the article, you need to have a understanding of `RSpec`

My understanding of continuous testing is that, there is a testing tool in the background, which while developing and modifying code, it will continuously notify you the broken of correct code. I usually set up the testing environment using `RSpec`, `Guard` and `Zeus`. The setup process may easily go wrong. Thus I made a note of the process.

## The tools we use

There are some tools we need to make testing __super fast__.

* `RSpec`: famous testing framework, complies to BDD concept.
* `Guard`: to guard the file change in Rails project.
* `Zeus`: a tool to re-use the Rails environment in development environment, but also can be used in testing.

To achieve continuous testing, `Guard` will watch the changes in the project, and re-run the updated test cases or all the related.

Some of the gems I also use in testing:

* `factory_girl_rails`: a mocking tool by Thoughtbot. One notice is that avoid using associates with it a lot
* `ffaker`: an much faster alternative to `Faker`, which generates fake data, such as company name, content, etc..

## Set up instructions

Starting from a fresh Rails 4 application, <span class="red">after creating the database(very important)</span>, add there gems to your `Gemfile`:

{% highlight ruby %}
group :development, :test do
  gem 'rspec-rails'
  gem 'guard-zeus'
  gem 'guard-rspec'
  gem 'guard-cucumber'
  gem 'childprocess'
  gem 'capybara'
  gem 'factory_girl_rails'
  gem 'rb-fsevent'
end

group :test do
  # if you need cucumber, uncomment these two lines
  # gem 'cucumber-rails', require: false
  # gem 'cucumber', '1.2.5'
  gem 'database_cleaner'
  gem 'email_spec'
  gem 'ffaker'
end
{% endhighlight %}

Then run these command in shell:

	rails g rspec:isntall
	guard init rspec

It will install `RSpec` and `Guard`.

{% highlight ruby %}
require 'rubygems'
require 'spork'
#uncomment the following line to use spork with the debugger
#require 'spork/ext/ruby-debug'

ENV["RAILS_ENV"] ||= 'test'
require File.expand_path("../../config/environment", __FILE__)
require 'rspec/rails'
# require 'rspec/autorun'

Dir[Rails.root.join("spec/support/**/*.rb")].each { |f| require f }
ActiveRecord::Migration.check_pending! if defined?(ActiveRecord::Migration)

RSpec.configure do |config|
  require 'email_spec'
  config.include(EmailSpec::Helpers)
  config.include(EmailSpec::Matchers)

  # Include FactoryGirl syntax
  config.include FactoryGirl::Syntax::Methods
  
  # Remove this line if you're not using ActiveRecord or ActiveRecord fixtures
  config.fixture_path = "#{::Rails.root}/spec/fixtures"

  # We use Database Cleaner. Change this one to false
  config.use_transactional_fixtures = false

  config.infer_base_class_for_anonymous_controllers = false

  config.order = "random"

  config.color_enabled = true

  # https://github.com/bmabey/database_cleaner#rspec-example
  config.before(:suite) do
    DatabaseCleaner.strategy = :transaction
    DatabaseCleaner.clean_with :truncation
  end

  config.before(:each) do
    DatabaseCleaner.start
  end

  config.after(:each) do
    DatabaseCleaner.clean
  end

end

{% endhighlight %}

Next, edit `Guardfile` a little bit. I will paste my `Guardfile` here:

{% highlight ruby %}
guard :rspec, cmd: 'zeus rspec --color --format documentation --fail-fast' do
  watch(%r{^spec/.+_spec\.rb$})
  watch(%r{^lib/(.+)\.rb$})     { |m| "spec/lib/#{m[1]}_spec.rb" }
  watch('spec/spec_helper.rb')  { "spec" }

  # Rails example
  watch(%r{^app/(.+)\.rb$})                           { |m| "spec/#{m[1]}_spec.rb" }
  watch(%r{^app/(.*)(\.erb|\.haml|\.slim)$})          { |m| "spec/#{m[1]}#{m[2]}_spec.rb" }
  watch(%r{^app/controllers/(.+)_(controller)\.rb$})  { |m| ["spec/routing/#{m[1]}_routing_spec.rb", "spec/#{m[2]}s/#{m[1]}_#{m[2]}_spec.rb", "spec/acceptance/#{m[1]}_spec.rb"] }
  watch(%r{^spec/support/(.+)\.rb$})                  { "spec" }
  watch('config/routes.rb')                           { "spec/routing" }
  watch('app/controllers/application_controller.rb')  { "spec/controllers" }

  # Capybara features specs
  watch(%r{^app/views/(.+)/.*\.(erb|haml|slim)$})     { |m| "spec/features/#{m[1]}_spec.rb" }

  # Turnip features and steps
  watch(%r{^spec/acceptance/(.+)\.feature$})
  watch(%r{^spec/acceptance/steps/(.+)_steps\.rb$})   { |m| Dir[File.join("**/#{m[1]}.feature")][0] || 'spec/acceptance' }
end
{% endhighlight %}

## Running the tests

Finally, let's test. Run `guard` to start the testing. Once the files being watched by `guard` updated, it will re-run the tests. Super fast. 


