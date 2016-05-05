---
layout: post
title: Effective Java 3 - Classes and Interfaces
excerpt:

tags: [java]
---

![](http://www.crazysmoove.com/memjug/javabooks-slides/images/Effective_Java.jpg)
<br />

* [13. Minimize the accessibility of classes and members](#13.-minimize-the-accessibility-of-classes-and-members)
* [14. In public classes, use accessor methods, not public fields](#14.-in-public-classes,-use-accessor-methods,-not-public-fields)
* [15. Minimize mutability](#15.-minimize-mutability)
* [16. Favor composition over inheritance](#16.-favor-composition-over-inheritance)
* [17. Design and document for inheritance or else prohibit it](#17.-design-and-document-for-inheritance-or-else-prohibit-it)
* [18. Interface is better than Abstract class](#18.-interface-is-better-than-abstract-class)
* [19. Interface for defining type only](#19.-interface-for-defining-type-only)
* [20. Prefer class hierarchies to tagged classes](#20.-prefer-class-hierarchies-to-tagged-classes)
* [21. Function object as strategies](#21.-function-object-as-strategies)
* [22. Favor static member classes over nonstatic](#22.-favor-static-member-classes-over-nonstatic)

* * *

## 13. Minimize the accessibility of classes and members 

Four accessibilities in Java:

* __private__: only accessible inside the class itself
* __package-private(default)__: accessible inside the package
* __protected__: accessible from subclasses of the class where it is declared, and from any class inside the package
* __public__: accessible from anywhere

It is not acceptable to make a class, interface or member a part of a package's exported API to facilitate testing. 

__Instance fields should never be public.__ if the field is not `final`, and it is public, that means you give up the control to limit the ability to store in this field. Also, __classes with public mutable fields are not thread-safe__.

For static field, it is ok if it declares to be `final`. The naming convention for these field is upper case.

A nonzero-length array is always mutable, so __it is wrong for a class to have a public static final array field, or an accessor that returns such a field.__ The elements inside the array can be modified. You can make a the public array private and add a public immutable list. Or return a clone of that private array

{% highlight java %}
private static final Thing[] PRIVATE_VALUES = { .. };
public static final List< Thing > VALUES = Collections.unmodifiableList(Arrays.asList(PRIVATE_VALUES));
{% endhighlight %}

## 14. In public classes, use accessor methods, not public fields 

The reason to do it is __flexibility__: easy to change to way to get and set the value, without affecting other parts of the code

However, if a class is package-private or is a private nested class, there is nothing inherently wrong with exposing its data fields.

## 15. Minimize mutability 

Some advices to make things immutable:

1. Don't provide any methods that modify the object's state(aka. _mutators_)
2. Ensure that the class can't be extended
3. Make all fields final
4. Make all fields private
5. Ensure exclusive access to any mutable components. If your class has any fields that refer to mutable objects, ensure that clients of the class cannot obtain references to these objects.

Immutable objects can be shared freely, they require no synchronization.

The only disadvantage of immutable classes is that they require a seperate object for each distinct value. Use lazy initialization.

To ensure the immutability, a class must not permit itself to be suclassed. __Static factory__ is a good way to implement it instead of constructor.

No methods may produce an externally visible change in the object's state.

#### Example: Complex number

{% highlight java %}
public class Complex {
	private final double re;
	private final double im;

	private Complex(double re, double im) {
		this.re = re;
		this.im = im;
	}

	public static Complex valueOf(double re, double im) {
		return new Complex(re, im);
	}

	public static Complex valueOfPolar(double rm, double theta) {
		return new Complex(r * Math.cos(theta), r * Math.sin(theta) );
	}
}
{% endhighlight %}

## 16. Favor composition over inheritance 

__Unlike method invocation, inheritance violates encapsulation.__ If superclass changes implementation, subclass will be affected.

If every A object has a B object inside, the class A is called __wrapper class__. This is the __Decorator design pattern__. This is not __delegation__, unless wrapper passes itself to the wrapped object.

## 17. Design and document for inheritance or else prohibit it 

If design for inheritance, the class must document its _self-use_ of overridable methods. For every public or protected methods, the documentation must indicate which overridable methods the method or constructor invokes

## 18. Interface is better than Abstract class 

Abstract class limits a class more than interface.

Interface is an ideal option for mixin definition of class.

__Skeleton Implementation(Abstract interface)__, makes it easy to provide implementation for interface. It combines the advantage of both interface and abstract class.

__Simulated Multiple Inheritance__: makes a private internal class implements an interface, so that the public class can implements multiple abstract class if needed.

#### Example: Skeleton Implementation

{% highlight java %}
public abstract class AbstractMapEntry<K,V> implements Map.Entry<K, V>
{
	public abstract K getKey();
	public abstract V getValue();

	// Simple Implementation
	public V setValue(V value) {
		throw new UnsupportedOperationException();
	}

	@Override 
	public boolean equals(Object o) {
		if (o == this)
			returh true;
		if ( ! (o instanceof Map.Entry))
			returh false;
		Map.Entry<?,?> arg = (Map.Entry) o;
		return 	equals(getKey(), arg.getKey()) &&
				equals(getValue(), arg.getValue());
	}
	
	private static boolean equals(Object o1, Object o2) {
		return o1 == null ? o2 == null : o1.equals(o2);
	}

	// Implements the general contract of Map.Entry.hashCode
	@Override
	public int hashCode(){
		return hashCode(getKey()) ^ hashCode(getValue());

	}

	private static int hashCode(Object obj) {
		return obj == null ? 0 : obj.hashCode();
	}
}

{% endhighlight %}

Skeleton implementation is designed for inheritance. The methods that don't have a concrete implementation can have a simple implementation, like `setValue()` in the example.

Once a interface is published and widely adopted, it is almost impossible to change it.

## 19. Interface for defining type only 

__Constant interface__: contains no methods, only static final fields. It is for defining constants. IT IS NOT A GOOD WAY TO USE INTERFACE. An example is `java.io.ObjectStreamConstants`. It is a bad example from Java API.

Better implementation is __Utility class__.  

{% highlight java %}
public class PhysicalConstants {
	private PhysicalConstants() {} //Prevents instantiation

	public static final double AVOGADROS_NUMBER = 6.02214199e23;
	public static final double BOLTZMANN_CONSTANT = 1.3806503e-23;

}
{% endhighlight %}

## 20. Prefer class hierarchies to tagged classes 

__Tagged class__: many seperated implementation dumped into one class. Tagged class is always too long, low performance.

Subclass is better than tagged class. Tagged class is a simulation of class hierarchies.

## 21. Function object as strategies 

This is __Strategy design pattern__.

#### Example: comparator

{% highlight java %}
class StringLengthComparator {
	private StringLengthComparator() {}
	public static final StringLengthComparator INSTANCE = new StringLengthComparator();
	public int compare(String s1, String s2) {
		return s1.length() - s2.length();
	}
}
{% endhighlight %}

Since `StringLengthComparator` is stateless, no fields, therefore it is better to be implemented as a singleton.

If we have many comparators, we'd better define a comparator interface. (Actually it is inside `java.util`)

{% highlight java %}
public interface Comparator<T> {
	public int compare(T t1, T t2);
}

{% endhighlight %}

It is also recommended to have a static strategy factory class, the concrete strategy implementation classes are inside the factory class, and they all implement the strategy interface.

## 22. Favor static member classes over nonstatic 

__Nested class__ is internal class, for serving the enclosing class. There are four types of nested class: __static member class__, __nonstatic member class__, __anonymouse class__ and __local class__.

__Static member class__ is just normal class that defined inside a class, no special purpose. It is an accesory of enclosing class.

__Nonstatic member class__ is much different than static member class. The instance of nonstatic member class may related to an enclosing instance. They may call the method of enclosing class. 

#### Example: nonstatic member class

{% highlight java %}
public class MySet<E> extends AbstractSet<E> {
	//...

	public Iterator<E> iterator() {
		return new MyIterator();
	}

	private class MyIterator implements Iterator<E> {
		// ...
	}
}
{% endhighlight %}

For this `MyIterator` class, if it is not required to visit enclosing class, then it may be declared as `static`.

__Anonymous class__ has no class name, cannot execute `instanceof` test. It is suitable for dynamicly create __function object__. or create __process object__ like `Runnable`, `Thread`. 

__Local class__ is just other local class.
