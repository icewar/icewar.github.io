---
layout: post
title: Effective Java 4 - Generics
excerpt:

tags: [java]
---

![](http://www.crazysmoove.com/memjug/javabooks-slides/images/Effective_Java.jpg)
<br />

* [23. Don't use raw types in new code](#23.-don't-use-raw-types-in-new-code)
* [24. Eliminate unchecked warnings](#24.-eliminate-unchecked-warnings)
* [25. Prefer `List` to `Array`](#25.-prefer-list-to-array)
* [26. Favor generic types](#26.-favor-generic-types)
* [27. Favor generic method](#27.-favor-generic-method)
* [28. Use bounded wildcards to increase API flexibility](#28.-use-bounded-wildcards-to-increase-api-flexibility)
* [29. Consider typesafe heterogeneous containers](#29.-consider-typesafe-heterogeneous-containers)

* * *


## 23. Don't use raw types in new code 

__Raw type__ generics is the type without the parameterized type. For example, `List` is the raw type of `List<E>`.

#### Example: bad

{% highlight java %}
// DON'T DO THIS
private final Collection stamps = ...;

stamps.add(new Coin());

for (Iterator i = stamps.iterator(); i.hasNext(); ) {
	// HERE COMES THE EXCEPTION
	Stamp s = (Stamp) i.next();
}
{% endhighlight %}

Replace the first line with: 

{% highlight java %}
private final Collection<Stamp> stamps = ...;
{% endhighlight %}

Using raw type will lose the security advantage of generics. Then why Java allow raw types? For historical reasons.

#### Difference between `List` and `List<Object>`

`List`, code likes this is avoiding type checking.

If `List lst`, `List<Object> lst1`, `List<String> lst2`, then `lst = lst2` is valid, but `lst1 = lst2` is invalid. `List<String>` is a subclass of `List`, but is not a subclass of `List<Object>`.

{% highlight java %}
public static void main(String[] args)
{
	List< String > strings = new ArrayList< String >();
	unsafeAdd(strings, new Integer(42));
	String s = strings.get(0);
}

private static void unsafeAdd(List list, Object o) {
	list.add(o);
}
{% endhighlight %}

Program will receive a warning at `list.add(o)`. I know you want to allow the element to be any type. You can use `List<?>` instead of `List` in `unsafeAdd`.

#### Difference between `List` and `List<?>`

`?`, the __unbounded wildcard type__, is a safe type. `null` cannot be put into `Collection<?>`.

#### Two exceptions: When to use raw type in new code

Generics information will be erase at runtime. It only takes effect at compile time.

1. In class literal(like `List.class`), we must use raw type. `List<String>.class` and `List<?>.class` are invalid.
2. `instanceof List<String>` is invalid.

Code below is a way to use `instanceof` when using generics

{% highlight java %}
if (o instanceof Set) {
	Set<?> m = ( Set<?> ) o;
}
{% endhighlight %}

#### Some types

__Bounded type parameter__: `<E extends Number>`

__Recursive type bound__: `<T extends Comparable<T>>`

__Bounded wildcard type__: `List<? extends Number>`

__Generic method__: `static <E> List<E> asList(E[] a)`

## 24. Eliminate unchecked warnings 

Eliminate every unchecked warnings that you can.

If the warning cannot be eliminated, and you can prove the code is safe, then you can use a `@SuppressWarnings("unchecked")` annotation to eliminate the warning. 

#### Example

{% highlight java %}
public < T > T[] toArray(T[] a) {
	if (a.length < size) {
		// This cast is correct because the array we're creating
		// is of the same type as the one passed in, which is T[].
		@SuppressWarnings("unchecked")
		T[] result = (T[]) Arrays.copyOf(elements, size, a.getClass());
		return result;
	}
	System.arraycopy(elements, 0, a, 0, size);
	if (a.length > size)
		a.[size] = null;
	return a;
}
{% endhighlight %}

When using `@SuppressWarnings("unchecked")` annotation, you must comment why it is correct and safe.

## 25. Prefer `List` to `Array` 

Array is __covariant__, which means if `Sub` is a subclass of `Super`, then `Sub[]` is a subclass of `Super[]`. 

List is __invariant__.

{% highlight java %}
/* This compiles */
Object[] objectArray = new Long[1];
objectArray[0] = "I don't fit in"; // Throws ArrayStoreException

/* This will not compile */
List<Object> ol = new ArrayList<Long>(); // compilation error
ol.add("I don't fit in");
{% endhighlight %}

This actually means, __array has fault, not generics__.

__Another difference between array and generics is__, array does type checking during runtime, while generics does that during compilation. Array throws exception if error occurs.

Generics does type checking while compilation, and then use __erasure__ to erase the parameterized type information in runtime. After erasure, generics can be used with unbounded generics.

#### Creating an array of a generic type, a parameterized type or a type parameter are illegal, because the type of array is not typesafe

This code is illegal

{% highlight java %}
List<String>[] stringLists = new List<String>[1]; // This one won't compile
List<Integer> intList = Arrays.asList(42);
Object[] object = stringLists;
objects[0] = intList;
String s = stringList[0].get(0);
{% endhighlight %}

If 1st line is correct, then 3rd line, it is correct, because at runtime, `stringList` is just `List` after erasure. Then 4th line, it is equivalent to the first element of `List` is a `List`(after erasure, but actually it is `List<Integer>`. 4th line is legal. But 5th line is illegal, we cannot get s, since it is a `Integer` 42.

Things like `E`, `List<E>`, `List<String>` is __non-reifiable__ type, which is a type that at runtime the information in the memory representation is little than compilation time. `List<?>` is legal.

__Solution__ is prefer `List<E>` instead of `E[]`. Less performance and simplexity, more secure and flexibility.

{% highlight java %}
static <E> E reduce(List<E> list, Function<E> f, E initVal) {
	E[] snapshot = (E[]) list.toArray(); // Locks list
	E result = initVal;
	for (E e : snapshot)
		result = f.apply(result, e);
	return result;
}
{% endhighlight %}

It has a warning `[unchecked] unchecked cast`. `toArray()` returns a Object[], casting to `E[]` is dangerous.

__Solution__ is:

{% highlight java %}
static <E> E reduce(List<E> list, Function<E> f, E initVal) {
	List<E> snapshot;
	synchronized(list) {
		snapshot = new ArrayList<E>(list);
	}

	E result = initVal;
	for (E e : snapshot)
		result = f.apply(result, e);
	return result;
}
{% endhighlight %}

## 26. Favor generic types 

We are programming a Stack class, `public class Stack<E>`. 

You may want to store the element in an array like `private E[] elements` inside the class. In the constructor, when you initialize `elements`, you will get a warning or error on `elements = new E[DEFAULT_INITIAL_CAPACITY]`. Because you cannot create a __non-reifiable__ type array.

There are two ways to solve this.

#### Solution 1

Initialize `elements = (E[]) new Object[DEFAULT_INITIAL_CAPACITY]`. You will get another warning says `unchecked cast`. The compiler cannot guarantee the casting is correct. You can use a `@SuppressWarnings("unchecked")` to avoid the warning. 

#### Solution 2

Change the type of `elements` to `Object[] elements`. Then you may get error when you do stack operations like on `E result = elements[--size]` you will get `incompatible types`. If you change it to `E result = (E) elements[--size]`, you will get a warning `unchecked cast`. Since `E` is a non-reifiable type, the compiler cannot to type checking when casting. Still you can use `@SuppressWarnings("unchecked")`.

#### Summary

Both solutions are ok. The difference is that first solution will annotate a whole array as `@SuppressWarnings`, which is more dangerous than the second solution. Thus the second one is better. But the second solution may require a lot of type casting to `E`,. That's why the first solution is more common in use.

Final code(using solution 1):

{% highlight java %}
// ... explain why you can suppress the warnings
@SuppressWarnings("unchecked")
public class Stack {
	private Object[] elements;
	private int size = 0;
	private static final int DEFAULT_INITIAL_CAPACITY = 16;

	public Stack () {
		elements = new Object[DEFAULT_INIT_CAPACITY];
	}
	
	public void push(Object e) {
		ensureCapacity();
		elements[size++] = e;
	}

	public Object pop() {
		if (size == 0)
			throw new EmptyStackException();
		Object result = elements[--size];
		elements[size] = null;
		return result;
	}

	public boolean isEmpty() {
		return size == 0;
	}

	private void ensureCapacity() {
		if (elements.length == size)
			elements= Arrays.copyOf(elements, 2*size+1);
	}
}

{% endhighlight %}

## 27. Favor generic method 

#### Example of generic method 

{% highlight java %}
public static <E> Set<E> union(Set<E> s1, Set<E> s2) {
	Set<E> result = new HashSet<E>(s1);
	result.addAll(s2);
	return result;
}
{% endhighlight %}

You can use bounded wildcard type to make it more flexible.

---

Generic has a mechanism called __type inference__. It will know what is the generic type you want to use.

There is a redundant in declaration of a generic object. `Map<String, List<String>> anagrams = new HashMap<String, List<String>>()`, the left side and right side both need the full type parameters. We can have a __generic static factory method__ to do it.

{% highlight java %}
public static <K, V> HashMap<K, V> newHashMap() {
	return new HashMap<K, V>
}

// calling the method 

Map<String, List<String>> anagrams = newHashMap(); // The type is inferenced from the return type

{% endhighlight %}

#### Example: generic singleton factory

If the object we generate from the generic static factory is a singleton, since generics use erasure mechanism, we may need to create many different types of singletons. 

Suppose we have an interface

{% highlight java %}
public interface UnaryFunction<T> {
	T apply(T arg);
}
{% endhighlight %}

Now we need an identity function, implement this `UnaryFunction`, we may need create a new one every time we use it for a new type.

The whole program:

{% highlight java %}
public interface UnaryFunction<T> {
	T apply(T arg);
}

public class Main
{
	// Generic singleton factory pattern
	private static UnaryFunction<Object> IDENTITY_FUNCTION = 
		new UnaryFunction<Object>() {
			public Object apply(Object arg) { return arg; }
	};

	// IDENTITY_FUNCTION is stateless and its type parameter is
	// unbounded so it's safe to share one instance across all types
	@SuppressWarnings("unchecked")
	public static <T> UnaryFunction<T> identityFunction() {
		return (UnaryFunction<T>) IDENTITY_FUNCTION;
	}
	
	public static void main(String[] args) {
		String[] strings = { "jute", "hemp", "nylon" };
		UnaryFunction<String> sameString = identityFunction();
		for (String s : strings) 
			System.out.println(sameString.apply(s));

		Number[] numbers = { 1, 2.0, 3L };
		UnaryFunction<Number> sameNumber = identityFunction();
		for (Number n : numbers)
			System.out.println(sameNumber.apply(n));
	}
}

{% endhighlight %}

This one will have an warning, since not all the `IDENTITY_FUNCTION` can be casted to `UnaryFunction<T>`. But we know it is safe here. 

#### Example: recursive type bound

How to express the constraint that in a list, every element is able to compare with another element in the list. For example, to get the maximum element from this type of list:

{% highlight java %}
public static <T extends Comparable<T>> T max(List<T> list) { 
	Iterator<T> i = list.iterator();
	T result = i.next();
	while (i.hasNext()) {
		T t = i.next();
		if (t.compareTo(result) > 0)
			result = t;
	}
	return result;
}
{% endhighlight %}

By doing so we ensure that type `T` is able to compare with the same type object.

## 28. Use bounded wildcards to increase API flexibility 

We have a piece of code:

{% highlight java %}
Stack<Number> numberstack = new Stack<Number>();
Iterable<Integer> integers = ... ;
numberStack.pushAll(integers);
{% endhighlight %}

You cannot push `integers` into `numberStack` because the types are not match. 

After using bounded wildcard:

{% highlight java %}
public void pushAll(Iterable< ? extends E> src) {
	for (E e : src)
		push(e);
}
{% endhighlight %}

If you also want a `popAll`:

{% highlight java %}
public void popAll(Collection< ? super E> dst)
{
	while (!isEmpty())
		dst.add(pop());

}
{% endhighlight %}

Pay attention to `Collection< ? super E>`.

__For maximum flexibility, use wildcard types on input parameters that represent producers or consumers.__

__PECS__: producer-extends, consumer-super. _producer_ provides things, will not change itself. _consumer_ use things, will change itself. So in previous example,, dst use the object from stack, it is a consumer.

#### Example

Apply PECS to the stack example in section 27: 

{% highlight java %}
public static <E> Set<E> union(Set< ? extends E > s1, Set< ? extends E > s2) { .. }

Set<Integer> integers = ...;
Set<Double> doubles = ...;
Set<Number> numbers = union(integers, doubles);
{% endhighlight %}

Notice that the return type of `union` is `Set<E>`.

Unfortunately, You will get an error: `incompatible types`. Because compiler cannot inference your type `E`.

The Solution is __explicit type parameter__. If the compiler cannot infer the correct type, we can try this.

{% highlight java %}
Set<Number> numbers = Union.<Number>union(integers, doubles);
{% endhighlight %}

#### More examples: recursive type bound

Let's look back at the `max()` int section 27. Apply PECS to that. Previous method is:

{% highlight java %}
public static <T extends Comparable< T > > T max(List< T > list)
{% endhighlight %}

Now become:

{% highlight java %}
public static <T extends Comparable< ? super T > > T max(List< ? extends T > list) {
	Iterator<T> i = list.iterator();
	T result = i.next();
	while( i.hasNext()) {
		T t = i.next();
		if (t.compareTo(result) > 0)
			result = t;
	}
	return result;
}
{% endhighlight %}

But it has a compilation error. It says `list` is not a `List<T>`. We need to replace the iterator with `Iterator< ? extends T > i= list.iterator()`.

## 29. Consider typesafe heterogeneous containers 

In Java 1.5, `Class` type becomes `Class<T>`. `String.class` returns a value of type `Class<String>`.

We have a `Favorites` class, to store one single favorite object for each type of things.

{% highlight java %}
public class Favorites {
	private Map< Class< ? >, Object> favorites = new HashMap< Class< ? >, Object>();

	public <T> void putFavorite(Class<T> type, T instance) {
		if (type == null)
			throw new NullPointerException("Type is null");
		favorites.put(type, instance);
	}
	public <T> T getFavorite(Class<T> type) {
		return type.cast(favorites.get(type));
	}
}


public static void main(String[] args) {
	Favorites f = new Favorites();
	f.putFavorite(String.class, "Java");
	f.putFavorite(Integer.class, 0xcafebabe);
	f.putFavorite(Class.class, Favorite.class);

	String favoriteString = f.getFavorite(String.class);

	System.out.println("%s\n", favoriteString);
}
{% endhighlight %}

We will get `Java`.

Notice that `Map< Class< ? >, Object>` can have any type of key.The value is `Object`, which means it does not guarantee the correct relationship between key and value.

To solve the problem, we can change `favorites.put(type, instance)` to `favorites.put(type, type.cast(instance))`.

Another problem of `Favorite` is, we cannot call something like `pushFavorite(List<String>.class, lst)`, because `List<String>` is non-reifiable. Currently it does not have a satisfying solution. 
