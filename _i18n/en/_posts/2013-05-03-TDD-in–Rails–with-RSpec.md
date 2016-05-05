---
layout: post
title: TDD in Rails With RSpec
subtitle:
cover_image: 
excerpt: "I found many developers being confused by all the levels of testing in Rails, and some concepts in software testing. Rails community has a very very strong awareness of TDD, and even BDD. Apps are designd using an Outside-in approach, which makes me feel really comfortable and also effective. "
tags: [testing, tdd, rails, rspec, ruby]
thumbnail: "http://jeffkreeftmeijer.com/images/fuubar.png"
---

![](http://jeffkreeftmeijer.com/images/fuubar.png)

> This article requires basic experience of TDD using UnitTest in Rails.

I found many developers being confused by all the levels of testing in Rails, and some concepts in software testing. Rails community has a very very strong awareness of TDD, and even BDD. Apps are designd using an Outside-in approach, which makes me feel really comfortable and also effective. 

Test suite is built while developing, not after developing. Although a test suite is not a silver bullet to 100% ensure the quality of your app, it does increase your confidence.

_There is a voice saying writing test suite sometimes makes development less effective. In practical yes, I have the same feeling sometimes. But it is not the test suite to be blamed, but the way to write it. Don't write the test cases for something you are already very confident with. More test cases you write will not prove you are a good TDD practitioner._

I meanly use RSpec + FactoryGirl. There are bunchs of good testing frameworks out there, such as Cucumber, for Acceptance test. I only develop small or medium sized app, and I feel Cucumber will make my development less effective. Even if I want to write Acceptance test cases, RSpec + Capybara will do.

__I will illustrate how to do testing in Rails using RSpec in this article, with some of my experience of developing.__ Let's start.

## 1. Get to know some basic concepts in testing using RSpec

### 1.1 Why use FactoryGirl?

Fixture inside the Rails framework has some cons. Mainly they are:

* Only one set of fixtures in a default Rails application.
* Each model has its own fixture file, and not easy to do data association.
* Not flexible. Static data

So we should use factories to replace fixtures. __FactoryGirl__ is the gem we are looking for. And it is from thoughtbot.

I will not talk about how to use FactoryGirl here. You just need to know that it can create object, with association. For example, if you are developing a blo	g system, a _User_ object has many _Blogs_, if you are still using fixture, then `user.blogs` may return nothing. 

### 1.2 What is mock and stub?

__Stub__ is a fake object that returns a predetermined value for a method call without calling the actual object. To define a stub, the code may look like this:

{% highlight ruby %}
thing.stubs(:name).returns("Fred")
{% endhighlight %}	

__Mock__ is similar to a stub, but in addition to returning the fake value, a mock object also sets a testable expectation that the method being replaced will actually be called in the test. If the method is not called, the mock obkect triggers a test failure. The code may look like this:

{% highlight ruby %}
thing.expects(:name).returns("Fred")
{% endhighlight %}	

Difference here is that in mock, the `:name` must be called to pass the test.

#### Mock and Stub in RSpec

Mock and stub have some different meaning in RSpec. Let's see the official definition

> The `mock_model` method generates a test double that acts like an instance of `ActiveModel`. The `stub_model`  generates an instance of a real object of `ActiveModel`. The benefit of `mock_model` is that it can mock some object that may not exist`. If you're working on a controller spec and you need a model that doesn't exist, you can pass`mock_model` a string and the generated obkect will act as though its an instance of the class named by that string.

> -- RSpec doc

To illustrate `mock_model`, there is a piece of sample code

{% highlight ruby %}
it "returns the correct name" do
	car = mock_model "Car"
	expect (car.class.name).to eq "Car"
{% endhighlight %}	

Various of specs will be discussed from highest level to the lower.

## 2. Feature Test

#### _What does it test?_

> Feature specs are high-level tests meant to __exercise slices of functionality
through an application.__ They should drive the application only via its
__external interface__, usually web pages.

> --- RSpec doc

From RSpec 2.0, capybara can only be used inside feature test. DSL `feature` and `scenario` will be used here. So at the time of writing, feature test is the only place you can simulate user interactions with the browser.

#### Sample

{% highlight ruby %}
feature "logged in user" do
	background do
		@user = FactoryGirl.create(:user)
		
		visit login_page_path
		
		fill_in "user_email", with: @user.email
		fill_in "user_password", with: @user.password
		click_button "Log in"
	end
	
	scenario "change password" do
		visit "/password"
		
		fill_in "password, with: "N3w_pass,d"
		fill_in "password_confirmation", with: "N3w_pass,d"
		click_button "Update"
		
		page.should have_content "success"
	end	
end
{% endhighlight %}	
	
The logic here is simple. You can start to feel the style RSpec doing test, and ignore the syntax details for now.
	
`background` is equavalent to the setup in other testing frameworks. Here I used FactoryGirl to create a sample user object. `fill_in`, `visit`, `click_button` are all from capybara DSL. Since the scenarios we will test below are all require user to log in, we do the login process inside the background code block.

The scenario here is for a logged in user to change password. It visit the change password url, and fill in the form, then click "Update" button. The website will redirect user to another page. But this page should display something like "success", such as "You have successfully changed your password".
		
## 3. Request Test

#### _What does it test?_

To be simple, if you want to test a function(I mean the function of your product, not function in programming) that needs the collaboration of multiple controllers, or in another word, sends multiple request, you should use request test.

Unlike feature test, you cannot check whether the webpage contains certain piece of string. But you should check whether the action redirects to certain path, or renders certain template.
		
## 4. Controller Test

#### _What does it test?_

Controller test allows only one request to the controller. So in most situation, it refers to call only one action in the controller.  And like request test, you can test the rendering, redirecting, variable values when being rendered, and http response code.

#### Sample

Let's test visiting a blog page. This page will show the content of the blog.

{% highlight ruby %}
describe BlogsController do
	let(:mock_blog) { FactoryGirl.create(:blog) }
	
	before { Blog.stub(:find).and_return( mock_blog ) }
	
	describe "GET show" do
		it "should display the post" do
			get :show
			assigns(:blog).should == mock_blog
		end
	end
end
{% endhighlight %}	
	
I first defines the `mock_blog` object using FactoryGirl. Then in the `before` block, I state no matter what parameter is, the `Blog.find()` will always return `mock_blog` during the testing. See how stub works? Then comes the real testing. The test sends a get request to the show page of `BlogsController`. `assigns(:blog)` will get the `@blog` in the template being rendered. I assert that this `@blog` should be `mock_blog`, because `Blog.find` will return `mock_blog`.

## 5. Model Test

#### _What does it test?_

Model test is what we called "Unit test". It is the simplest type of testing. In Rails, it will test the ActiveModel classes.

#### Sample

Check out the example from RSpec official:

{% highlight ruby %}
require "spec_helper"

describe Post do
  context "with 2 or more comments" do
    it "orders them in reverse chronologically" do
      post = Post.create!
      comment1 = post.comments.create!(:body => "first comment")
      comment2 = post.comments.create!(:body => "second comment")
      expect(post.reload.comments).to eq([comment2, comment1])
    end
  end
end
{% endhighlight %}	
	
Make sense?

## 6. Other tests

Other tests are almost the same as Model test, and easy to understand, so I won't talk about it here. They are:

* View test: test content of rendered template when given the model
* Helper test: test helpers methods. Very much like Model test
* Mailer test: test the mail sent
* Routing test: test whether a route is reachable

There is one more test exists but has nothing to do with RSpec. It is the performance test.
