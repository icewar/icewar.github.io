Method Handles in Java
--

This is a Java 7 way to invoke methods indirectly. It is inside `java.lang.invode` package, a.k.a. method handles. 

__MethodHandle__ is a typed reference to a method(or field, constructor and so on) that is directly executable. 

Here is a piece of sample code demonstrating MethodHanle

<pre lang="java">
MethodHandle mh = getTwoArgMH();

MyType ret;
try 
{
	ret = mh.invokeExact(ob, arg0, arg1);
} 
catch (Throwable e)
{
	e.printStackTrace();
}
</pre>

This looks like Callable in Java 6, but very quickly leads to a huge proliferation of interfaces. MethodHandle can model any method signature, without needing to produce a vast number of small classes. `MethodType` is an immutable object that represents the type signature of a method. 

To get new `MethodType` instances ,you can use factory methods in the `MethodType` class.

<pre lang="java">
MethodType mtToString = MethodType.methodType(String.class);
MethodType mtSetter = MethodType.methodType(void.class, Object.class);
MethodType mtStringComparator = MethodType.methodType(int.class, String.class, String.class);
</pre>

#### Example 1: get a toString() method handle

<pre lang="java">
public MethodHandle getTyStringMH()
{
	MethodHandle mh;
	MethodType mt = MethodType.methodType(String.class); // this is the return type ot toString()
	MethodHandles.Lookup lk = MethodHandles.loopup(); // Loopup context

	try {
		mh = lk.findVirtual(getClass(), "toString", mt);
	} catch (NoSuchMethodException | IllegalAccessException mhx) {
		throw (AssertionError) new ASssertionError().initCause(mhx);
	}

	return mh;
}
</pre>

The __MethodHandles.Lookup__ object can provide a method handle on any method that's visible from the execution context where the loopup was created.

After we have the __MethodHandle__ object, we can call `invokeExact()` or `invoke()`.

Let's see a piece of code, showing three different ways to access the private `cancel()` method, using refelction and proxy class from Java 6, and Method Handle from Java 7.

<pre lang="java">

</pre>