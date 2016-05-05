---
layout: post
title: Effective Java 2 - Methods Common to All Objects
excerpt:
tags: [java]

---

![](http://www.crazysmoove.com/memjug/javabooks-slides/images/Effective_Java.jpg)
<br />

* <a href="#8.-obey-the-general-contract-when-overriding-equals()">8. Obey the general contract when overriding `equals()`</a>

* <a href="#9.-always-override-hashcode-when-you-override-equals">9. Always override `hashCode` when you override `equals`</a>
* <a href="#10.-always-override-tostring()">10. Always Override `toString()`</a>
* [11. Override `clone` judiciously](#11.-override-clone-judiciously)
* [12. Comparable interface](#12.-comparable-interface)

* * *

## 8. Obey the general contract when overriding `equals()`

`equals()` should implement __equivalence relation__:

* __Reflexive__: for any `x` not null, `x.equals(x)` should return `true`
* __Symmetric__: for any `x, y` not null, if `y.equals(x)` returns `true`, then `x.equals(y)` returns `true`
* __Transitive__: for any `x, y, z` not null, if `x.equals(y)` returns `true`, and `y.equals(z)` returns `true`, then `x.equals(z)` should return `true`  
* __Consistent__: for any `x` not null, multiple invocations of `x.equals(y)` consistently return `true` or consistently return `false`, provided no information used in `equals` comparisons on th objects is modified
* for any `x` not null, `x.equals(null)` must return false

There is a fundamental problem of equivalence relations in OOP: __there is no way to extend an instantiable class and add a value component while preserving the `equals` contract__

#### To ensure Reflexivity

Difficult to violate this rule.

#### To ensure Symmetry

When implementing `equals()`, check type first, then do logic comparison.

#### To ensure Transitivity

Suppose class `ColorPoint` is a subclass of `Point`, we must override the `equals()` inherited from `Point`. The `equals()` of `ColorPoint` may be:

{% highlight java %}
@Override
public boolean equals(Object o) {
	if (!(o instanceof ColorPoint))
		return false;
	return super.equals(o) && ((ColorPoint) o).color == color;
}
{% endhighlight %}

This code violates symmetry, since a `Point p` with attributes as `ColorPoint cp`, `p.equals(cp)` will return `true`.

There is no perfect way to solve the problem. __Composition is better than inheritance__. A good way is:

{% highlight java %}
public class ColorPoint {
	private final Point point;
	private final Color color;

	public ColorPoint(int x, int y, Color color) {
		if (color == null)
			throw new NullPointerException();
		point = new Point(x, y);
		this.color = color;
	}

	public Point asPoint() {
		return point;
	}

	@Override public boolean equals(Object o) {
		if (!(o instanceof ColorPoint))
			return false;
		ColorPoint cp = ((ColorPoint) o);
		return cp.point.equals(point) && cp.color.equals(color);
	}
}
{% endhighlight %}

## 9. Always override `hashCode` when you override `equals`

Two distinct instances may be logically equal according to a class's `equals` method, but to Object's `hashCode` method, they're just two objects with nothing much in common. Therefore Object's `hashCode` method returns two seemingly random numbers instead of two equals numbers as required by the contract.

An example here:

{% highlight java %}

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import main.shared.Util;

final class PhoneNumber 
{
	private final short areaCode;
	private final short prefix;
	private final short lineNumber;
	
	public PhoneNumber(int areaCode, int prefix,
	                   int lineNumber)
	{
		rangeCheck(areaCode, 999, "area code");
		rangeCheck(prefix, 999, "prefix");
		rangeCheck(lineNumber, 9999, "line number");
		this.areaCode = (short) areaCode;
		this.prefix = (short) prefix;
		this.lineNumber = (short)lineNumber;
		
	}
	
	private static void rangeCheck(int arg, int max, String name) {
		if (arg < 0 || arg > max)
			throw new IllegalArgumentException(name + ": " +arg);
	}
	
	@Override
	public boolean equals(Object o) {
		if (o == this)
			return true;
		if (!(o instanceof PhoneNumber))
			return false;
		PhoneNumber pn = (PhoneNumber)o;
		return pn.lineNumber == lineNumber 
				&& pn.prefix == prefix
				&& pn.areaCode == areaCode;
	}
	
	// No hashCode
}

public class Main
{
	
	public static void main(String args[])
	{
		Map<PhoneNumber, String> m = new HashMap<PhoneNumber, String>();
		m.put(new PhoneNumber(707, 876, 5309), "Jenny");
		
		System.out.println(m.get(new PhoneNumber(707, 876, 5309)));
	}
}
{% endhighlight %}

We try to get the the same phone number from the map, but the output is `null`. 

Here we have two objects. One is inserted into the Map. Since we haven't override the `hashCode()` method, these two objects has different hash code, thus `put` method put the first object into a __hash bucket__, but `get` method is looking for the object in the other hash bucket. 

> If you are not familiar with __hash bucket__, here is my explanation. In hashing algorithms, hash table can be thought of a list of list, `List<List> lst`. Each element in `lst` has a unique hash code in `lst`, representing a list(this is the __hash bucket__ we were talking about).

You can have a `hashCode()` method, returns a good hash value, NOT something like `return 42;`.

A good hash function tends to produce unequal hash codes for unequal objects. This is exactly what is meant by the third provision of the `hashCode` contract. Ideally, a hash function should distribute any reasonable collection of unequal instances uniformly across all possible hash values. 

__A sample `hashCode()` method, with lazy instantiation__

{% highlight java %}
private volatile int hashCode; 

@Override
public int hashCode() {
	int result = hashCode;
	if (result == 0) {
		int A = 17, B = 31;
		result = B * result + areaCode;
		result = B * result + prefix;
		result = B * result + lineNumber;

		hashCode = result;
		return result; 
	}	
	return result;
}
{% endhighlight %}

Don't be tempted to exclude significant parts of an object from the hash code computation to improve performance.

## 10. Always Override `toString()`

## 11. Override `clone` judiciously

The `Cloneable` interface was intended as a `mixin interface` for objects to advertise that they permit cloning.

The `clone` method of `Object` is protected. You cannot, without reflection, invoke the `clone` method on an object merely because it implements `Cloneable`. Even a reflective invocation may fail, as there is no guarantee that the object has an accessible `clone` method.

The `Cloneable` interface has no methods, but determines the behavior of Object's protected clone implementation: if a class implements `Cloneable`, Object's `clone` method returns a field-by-field copy of the object; otherwise it throws `CloneNotSupportedException`.

A copy of an object means:

* x.clone() != x
* x.clone().getClass() == x.getClass()
* x.clone().equals(x)

`clone` method functions as another constructor. You must ensure that it does no harm to the original object and that it properly establishes invariants on the clone.

For something like a stack, where there are already many elements, a `clone` method should like this:

{% highlight java %}
@Override
public Stack clone() {
	try {
		Stack result = (Stack) super.clone();
		result.elements = elements.clone();
		return result;
	} catch (CloneNotSupportedException e){
		throw new AssertionError();
	}
} 
{% endhighlight %}

NOTE: if `elements` field is `final`, this may not work.

#### Example of `clone()` method of a HashTable class

{% highlight java %}
@Override
public class HashTable implements Cloneable {
	private Entry[] buckets = ...;
	private static class Entry {
		final Object key;
		Object value;
		Entry next;

		Entry(Object key, Object value, Entry next) {
			this.key = key;
			this.value = value;
			this.next = next;
		}
	}	
	
	private static class Entry {
		final Object key;
		Object value;
		Entry next;

		Entry(Object key, Object value, Entry next) {
			this.key = key;
			this.value = value;
			this.next = next;
		}

		Entry deepCopy() {
			return new Entry(key, value, next == null ? null : next.deepCopy() );
		}
	}

	public HashTable clone()
	{
		try {
			HashTable result = (HashTable) super.clone();
			result.buckets = new Entry[buckets.length];
			for (int i = 0; i < buckets.length; i++)
				if (buckets[i] != null)
					result.buckets[i] = buckets[i].deepCopy();
			return result;
		} catch (CloneNotSupportedException e) {
			throw new AssertionError();
		}
	}

	// other stuff
}

{% endhighlight %}
	
For long linked list, stack is easy to overflow. In `deepCopy()`, we can replace recursion with iteration.

{% highlight java %}
Entry deepCopy()
{
	Entry result = new Entry(key, value, next);

	for (Entry p = result; p.next != null; p = p.next)
		p.next = new Entry(p.next.key, p.next.value, p.next.next);
	return result;
}
{% endhighlight %}

#### Copy Constructor

To sum up, better not extends `Cloneable`. Copy Constructor is more appropriate and flexible.

## 12. Comparable interface

Like `equals()`, there are some rules that `compareTo()` must follow. In the following description, the notation `sgn(expression)` designates the sign function in math.

* The implementor must ensure `sgn(x.compareTo(y)) == -sgn(y.compareTo(x))` for all `x` and `y`.
* The implementor must ensure that the relation is transitive: `x.compareTo(y) > 0 && y.compareTo(z) > 0` implies `x.compareTo(z) > 0`
* The implementor must ensure that x.compareTo(y) == 0 implies that `sgn(x.compareTo(z)) == sgn(y.compareTo(z))`, for all z
* Optional requirement: `(x.compareTo(y) == 0 ) == (x.equals(y))`
