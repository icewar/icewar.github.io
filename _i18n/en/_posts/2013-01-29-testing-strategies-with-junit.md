---
layout: post
title: "Testing strategies with JUnit"
subtitle: 
cover_image: 
excerpt: "In order to do unit testing easier, one should keep a word in mind: Isolation. Try your best to isolate the irrelevant things from your class, and make them easy to config."
category: 
tags: [testing, java]
thumbnail: "http://www.ebooks-share.net/thumbs_big/95536.jpg"
---

* [How To Write Testable Code](#how-to-write-testable-code)
* [Several Words About TDD](#several-words-about-tdd)
* [Stubs and Mocks](#stubs-and-mocks)
* [Inversion of Control](#inversion-of-control)
* [In-Container Testing](#in--container-testing)

In order to do unit testing easier, one should keep a word in mind: Isolation. Try your best to isolate the irrelevant things from your class, and make them easy to config.

## How To Write Testable Code {#i1}

There are some common rules to write testable code.

#### * Never change the signature of a public method

If you change the signature of a public method, then you need to change every call to site in the application and unit tests. In the open source world, and for any API made public by a commercial product, life can get even more complicated — many people use your code, you should make it backward compatible.

#### * Reduce Dependencies

Unit tests verify your code in isolation. Your unit tests should instantiate the class you want to test, use it, and assert its correctness. Do not instantiate other classes.

#### * Create Simple Constructors

When testing, there are something we need to do:

* Instantiate the class to test
* Set the calss into a particular state
* Assert the final state of the class

With complicated construcotr, we might mix the first and second points. This code is hard to maintain and test.

#### * Law of Demeter

Also known as the Least Knowledge principle: one class should know only as much as it needs to know.

Consider the following code:

{% highlight java %}

class Car {
    private Driver driver;
    
    Car(Context context) {
        this.driver = context.getDriver();
    }
}

{% endhighlight %}

`Car` should not know the `Context` object.

Here is a recommended solution

{% highlight java %}
Car(Driver driver) {
    this.driver = driver;
}
{% endhighlight %}

#### * Avoid hidden dependendcis and global state

Global state makes it possible for many clients to share the global object.

See the following code:

{% highlight java %}
public void reserver() {
    DBManager manager = new DBManager();
    manager.initDatabase();
    Reservation r = new Reservation();
    r.reserve();
}
{% endhighlight %}

The `DBManager` implies a global state. And the `Reservation` class hides its dependency on the database manager from the programmer because the PAI doesn’t give us a clue.

Here is a better implementation

{% highlight java %}
public void reserver() {
    DBManager manager = new DBManager();
    manager.initDatabase();
    Reservation r = new Reservation(manager);
    r.reserve();
}
{% endhighlight %}

Here, the `Reservation` object should be able to function only if it has been configured with a database manager.

#### * Favor Generic Methods

In order to achive isolation in testing, you need some articulation points in your code, where you can easily substitute your code with the test code. With polymorphism, the moethod you’re calling can be determined at runtime. Static method does not have polymorphism, sometimes makes testing difficult.

#### * Faver composition over inheritance

#### * Faver polymorphism over conditionals

## Several Words about TDD

TDD, Test-Driven-Development, let the tests to drive you do programming. Someone says that there are two phases in TDD, someone says three. It doesn’t matter much.

I mainly agree with the three-phases opinion. They are:

* Fail the test
* Implement and Pass the test
* Refactor

Refactor is optional sometimes.

## Stubs and Mocks

`Stub`: Suppose you are development a complicated system. When the class or module is not fully implemented but you still want to test it, you can extends the existing class, and make the un-finished part working by just put in simple logic. For instance, if a method should query data from the database but it is not implemented, then you can stub it, make it return some values. Stubs does not change the existing code, but instead adapt to provide seamless integration. Stub is always used for coarse-grained software test, like integration test.

`Mock`: fully fake class or module. It never has real business logic, just return values. It is very similar to stub. But only stubs is a extending the existing code, may contain real business logic, but mock does not have any real business logic. It is a brand new fake module.

__Talking about flexibility__: someone may feel troublesome to write tests. Well, if your code is too inflexible for some tests to use, then your code is really inflexible, and you should redesign it.

In mocking techniques, sometimes we want to verify that a method has been called exactly some times. This is called expectation. Many mocking frameworks, like easymock, do provide the expectation functionality.

#### Comparison

Stub often requires less code than mock. But mocks are always running faster, especially if the function need to connect to database or depends on network connection.

## Inversion of Control

Talking again about IoC, that is what I mentioned at the beginning of this article. Traditionally In a class, say A, if we want to create an object B, which is an instance of another class, we just create it in A. But from the testing point of view, if we are writing unit test for A, then the correctness of test depends on the correctness of B, since the creation of B is inside A. To remove this dependency, that’s why we need to inverse the creation(control) of B to outside of A. We may pass the created object B to class A or whatever. There are many good IoC containers in the market. Most famous is Spring. Guice is very popular these days.

## In-Container Testing

Stubs and Mocks are both Out-Container Testing techniques. In-Container testing means that the object being tested must live in a environment, we call it container. For example, to test `SampleServlet`, it should be run with `HttpServletRequest` and `HttpSession`. Maybe it need live data. So it is the testing inside the container, like Tomcat.

This will be discussed in more details in the future.
