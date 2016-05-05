---
layout: post
title: Effective Java 6 - Methods
excerpt:
tags: [java]
---

![1](http://www.crazysmoove.com/memjug/javabooks-slides/images/Effective_Java.jpg)
<br />

* [38. Parameter validation](#38.-parameter-validation)
* [39. Make defensive copies when needed](#39.-make-defensive-copies-when-needed)
* [40. Design method signatures carefully](#40.-design-method-signatures-carefully)
* [41. Use overloading judiciously](#41.-use-overloading-judiciously)
* [42. Use varargs judiciously](#42.-use-varargs-judiciously)
* [43. Return empty arrays or collections, not nulls](#43.-return-empty-arrays-or-collections,-not-nulls)
* [44. Write doc comments for all exposed API elements](#44.-write-doc-comments-for-all-exposed-api-elements)

* * *

## 38. Parameter validation 

If parameter is not valid, a method should throw exceptions, other than continuing the method and return wrong result. Common exceptions are `IllegalArgumentException`, `IndexOutOfBoundsException`, `NullPointerException`.

For unexported method(such as private method), usually we use assertion to check their parameters

{% highlight java %}
private static void sort(long a[], int offset, int length) {
	assert a != null;
	assert offset >= 0 && offset <= a.length;
	assert length >= 0 && length <= a.length - offset;
	// ...

}
{% endhighlight %}

If assertion failed, then program will throw `AssertionError`.

If the validation is costly, then validation can be performed implicitly in the process of doing the computation.

If there is exception during computation and the program throws another type of exception due to invalid parameter, we should use __exception translation__.

## 39. Make defensive copies when needed 

You must program defensively, with the assumption that clients of your class will do their best to destroy its invariants.

More likely, your class will have to cope with unexpected behavior resulting from honest mistakes on the part of programmers using your API.

#### Example

{% highlight java %}
public final class Period {
	public Period(Date start, Date end) {
		if(start.compareTo(end) > 0)
			throw new IllegalArgumentException( start + " after " + end);
		this.start = start;
		this.end = end;
	}

	public Date start() {
		return start;

	}

	public Date end() {
		return end;
	}

	// ...
}

Date start = new Date();
Date end = new Date();
Period p = new Period(start, end);
end.setYear(78); // modifies internals of p
{% endhighlight %}

To protect the `Period` instance internals, we need to make __defensive copy__ for every variant parameter.

{% highlight java %}
public Period(Date start, Date end)
{
	this.start = new Date(start.getTime());
	this.end = new Date(end.getTime());

	if (this.start.compareTo(this.end) > 0)
		throw new IllegalArgumentException( start + " after " + end);

}
{% endhighlight %}

__The defensive copy is before the parameter validation, and the validation is for the defensive copy, not the original parameters.__

Don't use the `clone` method to make a defensive copy of a parameter whose type is subclassable by untrusted parties.

Another way to attack is:

{% highlight java %}
Period p = new Period(start, end);
p.end().setYear(78);
{% endhighlight %}

To defend, return a copy of internal object:

{% highlight java %}
public Date start() {
	return new Date(start.getTime());
}

public Date end() {
	return new Date(end.getTime());
}
{% endhighlight %}

Use immutable objects as components of your objects,

If the class trust the caller of the class will not modify the internals, then no defensive copy is allowed. But it must be documented that the caller cannot modify the return value or parameter. 

## 40. Design method signatures carefully 

* Choose method names carefully
* Don't go overboard in providing convenience methods. Too many methods makes a class complex.
* Avoid long parameter list
* Prefer two-element enum types to `boolean` parameters

## 41. Use overloading judiciously 

#### Example: check the type of `Collection`:

{% highlight java %}
public class CollectionClassifier {
	public static String classify(Set< ? > s){
		return "Set";
	}

	public static String classify(List< ? > s){
		return "List"
	}

	public static String classify(Collection< ? > s){
		return "Unknown Collection";
	}

	public static void main(String[] args) {
		Collection< ? >[] collections = {
			new HashSet< String >(),
			new ArrayList< BigInteger >(),
			new HashMap< String, String>().values()
		};

		for (Collection< ? > c : collections) 
			System.out.println(classify(c));
	}
}
{% endhighlight %}

The output will be three `Unknown Collection`. Because in the for-loop, all the elements are compiled to be `Collection<?>`. Overloading will not dynamicly choose the right method like overriding does.

The correct way is:

{% highlight java %}
public static String classify(Collection< ? > c) {
	return c instanceof Set ? "Set" : c instanceof List ? "List" : "Unknown Collection";
}
{% endhighlight %}

Better strategy to use overloading is never to export two overloadings with the same number of parameters. If a method uses varargs, not to overload it at all.

For example, int `ObjectOutputStream` class, the `write` method has many different expressions, such as `writeBoolean` and `writeInt`.

#### Example

{% highlight java %}
public static Test {
	public static void main(String[] args) {
		List< Integer > list = new ArrayList< Integer >();

		for (int i = -3; i < 3; i++) 
			list.add(i);
		
		for (int i = 0; i < 3; i++)
			list.remove(i);

		System.out.println(list);
	}
}
{% endhighlight %}

The output is `[-2, 0, 2]`. `remove(int)` in `List` will remove the element at given position. To remove first appearing element, use `remove(E)`, which should be `remove((Integer) i)` here.

## 42. Use varargs judiciously 

For a method `void func(int... args)`, if user has no input, it will fail at runtime but not compile time. One way to solve the problem is to change it to `void func(int firstArg, int... remainingArgs)`.

#### Example: right way to print an array

{% highlight java %}
System.out.println(Arrays.toString(ary));
// System.out.println(Arrays.asList(ary)); WILL NOT HAVE EXPECT OUTPUT
{% endhighlight %}

## 43. Return empty arrays or collections, not nulls 

## 44. Write doc comments for all exposed API elements 

Java doc uses specially formated documentation comment to generate API doc.

Doc comments should state all the _preconditions_ and _postconditions_, and also __side effect__. Side effect is the observable change after running this. For example, if a method starts a backend thread, then the doc should state it.

Some common elements in doc: `@param`, `@return`, `@throws`, html element, `{@code}` piece, `{@literal}` to avoid escaping of `.` or other characters

