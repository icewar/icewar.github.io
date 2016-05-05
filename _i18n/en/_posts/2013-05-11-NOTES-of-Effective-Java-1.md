---
layout: post
title: Effective Java 1 - Creating and Destroying Object
excerpt:
tags: [java]
thumbnail: "http://www.crazysmoove.com/memjug/javabooks-slides/images/Effective_Java.jpg"
---

![](http://www.crazysmoove.com/memjug/javabooks-slides/images/Effective_Java.jpg)
<br />

* [1. Use static factory method instead of constructor](#1.-use-static-factory-method-instead-of-constructor)
* [2. Consider a builder when faced with many constructor parameters](#2.-consider-a-builder-when-faced-with-many-constructor-parameters)
* [3. Enforce the singleton property with a private constructor or an enum type](#3.-enforce-the-singleton--property-with-a-private-constructor-or-an-enum-type)
* [4. Enforce noninstantiability with a private constructor](#4.-enforce-noninstantiability-with-a-private-constructor)
* [5. Avoid creating unnecessary objects](#5.-avoid-creating-unnecessary-objects)
* [6. Eliminate obsolete object references](#6.-eliminate-obsolete-object-references)
* [7. Avoid using Finalizers](#7.-avoid-using-finalizers)

* * *

## 1. Use static factory method instead of constructor

Class should provide a public __static factory method__. It is a static method returing an instance.

#### Example

{% highlight java %}
public static Boolean valueOf(boolean b) {
	return b ? Boolean.TRUE : Boolean.False;
}

{% endhighlight %}

#### Pros: compare to constructor

1. Easy to customize name, like `BigInteger.probablePrime` to return prime numbers
2. No need to create new object when called.
3. Able to return subclass instance

#### Cons

1. Classes without public or protected constructors cannot be subclassed.
2. They are not readily distinguishable from other static methods.

`java.util.Collections` have 32 static factory methods

#### More

The class of the object returned by a static factory method need not even exist at the time the class containing the method is written. Such flexible static factory methods form the basis of _service provider frameworks_. It is such kind of a system: multiple service provider implement one service, the system provide multiple implementation for client, and decouple them from implementations. A _service provider frameworks_ have three important components: 

* __Service Interface__: implement the functionality
* __Provider Registration API__: client register the service
* __Service Access API__: client get service instance

and one optional component:

* __Service Provider Interface__: for provider to create the implementation of service.

Take __JDBC__ as an example, `Connection` is the service interface, `DriverManager.registerDriver` is the provider registration API, `DriverManager.getConnection` is the service access API, and `Driver` is the service provider interface.

## 2. Consider a builder when faced with many constructor parameters

> Don't write telescoping constructor pattern, because it is hard to write client code when there are many parameters, and harder still to read it

### JavaBeans Pattern

One parameterless constructor to create the object, and the call setter methods to set each required parameter and each optional parameter of interest.

#### Cons

1. If construction process is split across multiple calls, a JavaBean may be in an inconsistent state partway through its construction.
2. JavaBeans pattern precludes the possibility of making a class immutable, because of setters.

### Builder Pattern

Client use required parameters to call the constructor(or static factory method) to get a builder object. Then client config the builder, and call the `build` method to create the immutable instance.

#### Example

{% highlight java %}
public class NutritionFacts {
	private final int servingSize;
	private final int servings;
	private final int calories;
	private final int fat;
	private final int sodium;
	private final int carbohydrate;

	public static class Builder {
		// required parameters
		private final int servingSize;
		private final int servings;

		// optional parameters - ini with default values
		private int calories = 0;
		private int fat = 0;
		private int carbohydrate = 0;
		private int sodium = 0;

		public Builder(int servingSize, int servings) {
			this.servingSize = servingSize;
			this.servings = servings;
		}

		public Builder calories(int val)
		{ calories = val; return this; }
		public Builder fat(int val)
		{ fat = val; return this; }
		public Builder carbohydrate(int val)
		{ carbohydrate = val; return this; }
		public Builder sodium(int val)
		{ sodium = val; return this; }

		public NutritionFacts build()
		{ return new NutritionFacts(this); }

	}
	private NutritionFacts(Builder builder)
	{
		servingSize = builder.servingSize;
		servings = builder.servings;
		calories = builder.calories;
		fat = builder.fat;
		sodium = builder.sodium;
		carbohydrate = builder.carbohydrate;
	}
}
{% endhighlight %}

For creating a NutritionFacts object

{% highlight java %}
NutritionFacts cocaCola = new NutritionFacts.Builder(240, 8).calories(100).sodium(35).carbohydrate(27).build();
{% endhighlight %}

A builder whose parameters have been set makes a fine _Abstract Factory_. Client can pass such a builder to a method to enable the method to create one or more objects for the client. 

For example, we need to create a tree.

{% highlight java %}
public interface Builder< T > {
	public T build();
}

Tree buildTree(Builder< ? extends Node > nodeBuilder) { 
	// .. 
}
{% endhighlight %}


## 3. Enforce the singleton property with a private constructor or an enum type

To make a singleton class that is implemented using either of the previous approaches serializable, it is not sufficient merely to add `implements Serializable` to its declaration. To maintain the singleton guarantee, you have to declare all instance fields `transient` and provide a `readResolve` method. Otherwise, each time a serialized instance is deserialized, a new instance will be created, leading to spurious `Elvis` sightings. To prevent this, add this `readResolve` method to the `Elvis` class:

{% highlight java %}
private Object readResolve() {
	// Return the one true Elvis and let the garbage collector
	// take care of the Elvis impersonator.
	return INSTACE;
}
{% endhighlight %}

As on release of Java 1.5, there is a approach to implementing singletons

{% highlight java %}
// Enum singleton = the preferred approach
public enum Elvis {
	INSTACE;

	public void leaveTheBuilding() { .. }
}
{% endhighlight %}

It provides the serialization machinery for free, and provides an ironclad guarantee against multiple instantiation, even in the face of sophisticated serialization or reflection attacks. Now it is the best way to implement a singleton.

## 4. Enforce noninstantiability with a private constructor

## 5. Avoid creating unnecessary objects

Try to use static factory method on immutable class, or mutable variables that known will not be changed.

#### Example

A method to check whether a person is born during baby boom. It will actually check whether the person was born between 1946 to 1964.

{% highlight java %}
public class Person {
	private final Date birthDate;

	// Other fields 

	// DON'T DO THIS
	public boolean isBabyBoomer()
	{
		Calendar gmtCal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
		gmtCal.set(1946, Calendar.JANUMARY, 1, 0, 0, 0);
		Date boomStart = gmt.getTime();
		gmtCal.set(1965, Calendar.JANUMARY, 1, 0, 0, 0);
		Date boomEnd = gmt.getTime();
		return birthDate.compareTo(boomStart) >= 0 &&
			birthDate.compareTo(boomEnd) < 0;
		
	}
}
{% endhighlight %}

Instead, we can do:

{% highlight java %}
public class Person {
	private final Date birthDate;

	// Other fields 

	private static final Date BOOM_START;
	private static final Date BOOM_END;

	static {
		Calendar gmtCal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
		gmtCal.set(1946, Calendar.JANUMARY, 1, 0, 0, 0);
		BOOM_START = gmt.getTime();
		gmtCal.set(1965, Calendar.JANUMARY, 1, 0, 0, 0);
		BOOM_END = gmt.getTime();
	}

	// DON'T DO THIS
	public boolean isBabyBoomer()
	{
		return birthDate.compareTo(BOOM_START) >= 0 &&
			birthDate.compareTo(BOOM_END) < 0;
		
	}
}
{% endhighlight %}

#### Example

{% highlight java %}
public static void main(String[] args) {
	Long sum = 0L;
	for (long i=0; i < Integer.MAX_VALUE; i++)
		sum += i;
	System.out.println(sum);
}
{% endhighlight %}

This is program is slow. We should change `Long` to `long`.

#### Principle

The princeple is to reuse those objects that cost a lot to create as many times as possible.

## 6. Eliminate obsolete object references

If a stack grows and then shrinks, the objects that were popped off the stack will not be garbage collected, even if the program using the stack has no more references to them. This is because the stack maintains _obsolete references_ to these objects. An obsolete reference is simply a reference that will never be dereferenced again. If an object references is unintentionally retained, not only is that object excluded from garbage collection, but so too are any objects referenced by that object, and so on.

One way to resolve this is: null out references once they become obsolete.

#### Example

{% highlight java %}
public Object pop() {
	if (size == 0)
		throw new EmptyStackException();
	Object result = elements[--size];
	elements[size] = null;
	return result;
}
{% endhighlight %}

#### When to null out the reference?

Whenever a class manages its own memory. the programmer should be alert for memory leaks. Whenever an element is freed, any object references contained in the element should be nulled out.

Storage Pool contains elements array. Array space is _allocated_, but elements inside is unknow to the garbage collector.

__Another source of memory leak is listeners and callbacks.__ Listeners need to be deregistered when not used any more.. The best way to ensure that callbacks are garbage collected promptly is to store only _weak references_ to them, for example, by storing them only as keys in a `WeakHashMap`.

## 7. Avoid using Finalizers

Using finalizer will lead to unstatble, low performance, and portability problems. 

The problem of finalizer is that the time to run it is unpredictable. It is not even guarantee that the finalizer will be run.

One more problem is: it is about 430 times slower to create and destroy objects with finalizer.

__Provide an explicit termination method__, and require clients of the class to invoke this method on each instance when it is no longer needed. __Use try..catch..finally__.

{% highlight java %}
Foo foo = new Foo();
try {
	// Do what must be done with foo
} finally {
	foo.terminate(); // explicit termination method
}
{% endhighlight %}

#### Act as a "safety net" in case the owner of an object forgets to call its explicit termination method

The finalizer should log a warning if it finds that the resource has not been terminated

The four classes cited as examples of the explicit termination method pattern (__FileInputStream, FileOutputStream, Timer and Connection__) have finalizers that serve as swafy nets in case their termination methods aren't called.
