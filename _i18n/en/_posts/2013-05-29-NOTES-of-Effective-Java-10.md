---
layout: post

title: Effective Java 10 - Serialization
excerpt: Notes of Effective Java 10, Serialization
tags: [java]

---

![](http://www.crazysmoove.com/memjug/javabooks-slides/images/Effective_Java.jpg)
<br />

* [74. implement Serializable judiciously](#74.-implement-serializable-judiciously)
* [75. Consider using a custom serialized form](#75.-consider-using-a-custom-serialized-form)
* [76. Write `readObject` methods defensively](#76.-write-readobject-methods-defensively)
* [77. For instance control, prefer enum types to `readResolve`](#77.-for-instance-control,-prefer-enum-types-to-readresolve)
* [78. Consider serialization proxies instead of serialized instances](#78.-consider-serialization-proxies-instead-of-serialized-instances)

* * *

## 74. implement Serializable judiciously 

Once a `Serializable` interface is published, it decreases the flexibility to change a class's implementation. You have to support serialization forever.

Serialization and deserialization are normally implemented by `ObjectOutputStream.putFields` and `ObjectInputStream.readFields`. 

You should design a high quality serialization method, that can be used for a long time.

Every serializable class has a unique ID `private static final long serialVersionUID`. If you don't have one, system will create a UID based on the structure of this class.

Another cost of implementing `Serializable` is that __it increases the likelihood of bugs and security holes.__ Usually we create an object using constructor. Serialization provides another extralinguistic mechanism to create an object. Deserialization is a hidden constructor. Deserialization constructor must follow all the constraints in the real constructor, otherwise it will be attacked. 

The third cost of serialization is, as new version releasing, it increases the testing burden. When new version released, we need to check whether can create an object using new version, and deserialize in the old version. 

#### Some rules

If a class is serializable, then all its component classes need to be serializable. 

__A class designed for inheritance should try best to avoid implementing serializable.__

Examples of implementing `Serializable`: `Throwable` implements `Serializable`, therefore RMI exception can be sent from server to client.

For a class that can be serialized and the initial values of instance field are special, then we need to add a `readObjectNoData` to the class. For more information, please check Java documentation about Serialization.

Serialization requires the implementing class to have all the field serializable, which makes a class designed for inheritance difficult to be serializable. In Addition, if a parent class does not have a parameterless constructor, the subclass is surely not serializable. Therefore, __to make a class designed for inheritance nonserializable, you should have a parameterless constructor.__

__If you want to have a nonserializable parent class, and a serializable subclass__, you need to make the parent class a __protected parameterless constructor__. 

Anyway, you have to cautiously make a decision whether subclass is serializable.

## 75. Consider using a custom serialized form 

__The default serialized form is likely to be appropriate if an object's physical representation is identical to its logical content.__ For example, some classes that contain only property fields.

Using the default serialized form when an object's physical representation differs substantially from its logical data content has four disadvantages:

* __It permanently ties the exported API to the current internal representation.__ Internal class, field becomes part of the public API. If the internal is changed in the future, the actual class still need to support the old version of internal.
* __It can consume excessive space.__ Redundant information will also be serialized.
* __It can consume excessive time.__ Serialization traverses the topology graph of class relationship.
* __It can case stack overflows,__ due to the traversal of topology graph.

#### Example: `StringList`

Suppose `StringList` is a class store a list of `String`s. The logical representation should only contains all the elements, and maybe the number of elements. But the physical representation is the list itself, contains the linkage between elements. 

{% highlight java %}

public final class StringList implements Serializable
{

	private transient int size = 0;
	private transient Entry head = null;
	
	// No longer serializable
	private static class Entry {
		String data;
		Entry next;
		Entry previous;
	}
	
	public final void add(String s) { 
		// ...
	}
	
	/**
	 * Serialize this {@code StringList} instance.
	 * 
	 * @serialData The size of the list (the number of strings it contains) is emitted ({@code int}), followed
	 * by all of its elements (each a {@code String}), in the proper sequence.
	 * @params
	 * @throws IOException
	 */
	private void writeObject(ObjectOutputStream s) throws IOException {
		s.defaultWriteObject();
		s.writeInt(size);
		
		// Write out all elements in the proper order.
		for (Entry e = head; e != null; e = e.next)
			s.writeObject(e.data);
	}
	
	private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
		s.defaultReadObject();
		int numElements = s.readInt();
		
		// Read in all elements and insert them in list
		for (int i = 0; i < numElements; i++)
			add((String) s.readObject() );
	}
	// ...
}

{% endhighlight %}

`transient` field means to omit it from the default serialization.

`defaultWriteObject` writes the non-static and non-transient fields of the current class to this stream. It may only be called from the `writeObject` method of the class being serialized.

It is recommended to call `defaultWriteObject` and `defaultReadObject`, even when all the fields are transient. It improves the flexibility. In the future if we add non-transient field to the class, the serialization will still be successful.

`writeObject` has commented documentation, because it defines the serialization form. `@serialData` tells Javadoc to include this part as serialization information.

### Mark fields as `transient` when needed. 

If you are using the default serialization form, when deserializing, all the transient field will have be assigned the default value: `null` for objects, `0` for number, and `false` for boolean, etc..

`private static final long serialVersionUID` is to avoid the incompatibility of default UID between different versions.

All of our effort here is to resolve the __serialization compatibility__ problem.

## 76. Write `readObject` methods defensively 

`readObject` method is another public constructor. It must validate the parameters before deserialization, and also do defensive copying. Otherwise, attacker will create an illegal object from it.

Attacker can manually fake a serialized form, by modifying a normal one based on some documentation.

{% highlight java %}
// Example from #39
public final class Period implements Serializable{
	private final Date start;
	private final Date end;

	public Period(Date start, Date end)
	{
		this.start = new Date(start.getTime());
		this.end = new Date(end.getTime());

		if (this.start.compareTo(this.end) > 0)
			throw new IllegalArgumentException( start + " after " + end);

	}

	public Date start() {
		return new Date(start.getTime());
	}

	public Date end() {
		return new Date(end.getTime());
	}

	public String toString() { return start + " - " + end; }
	// ...
}

public class BogusPeriod {
	private static final byte[] serializedForm = new byte[] { 
		// ...
	};

	public static void main(String[] args) {
		Period p = (Period) deserialize(serializedForm);
		System.out.println(p);
	}

	private static Object deserialize(byte[] sf) {
		try {
			InputStream is = new ByteArrayInputStream(sf);
			ObjectInputStream ois = new ObjectInputStream(is);
			return ois.readObject();
		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
	}
}
{% endhighlight %}

To solve the problem, you can provide a `readObject` method for `Period`.

{% highlight java %}
private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
	s.defaultReadObject();

	if (start.compareTo(end) > 0)
		throw new InvalidObjectException(start + " after " + end);
}
{% endhighlight %}

It still has a small but severe problem. Attacker can create a class to modify a valid `Period` object.

{% highlight java %}
class MutablePeriod {
	public final Period period;
	public final Date start;
	public final Date end;
	
	public MutablePeriod() {
		try
		{
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(bos);
			
			out.writeObject(new Period( new Date(), new Date()));
			
			byte[] ref = { 0x71, 0, 0x7e, 0, 5 };
			bos.write(ref);
			ref[4] = 4;
			bos.write(ref);
			
			ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()));
			period = (Period) in.readObject();
			start = (Date) in.readObject();
			end = (Date) in.readObject();
		}
		catch (Exception e)
		{
			throw new AssertionError(e);
		}
	}
	
}

public class Main
{
	public static void main(String args[]){

		MutablePeriod mp = new MutablePeriod();
		Period p = mp.period;
		Date pEnd = mp.end;
		
		pEnd.setYear(78);
		System.out.println(p);
		
		pEnd.setYear(69);
		System.out.println(p);
	}
}
{% endhighlight %}

This demo show that a `Period` object internal can be changed by `MutablePeriod` object. If attacker creates a `MutablePeriod` object, and pass the `mp.period` to your program, and the security of your program depends on the immutability of `Period`, then you will be hacked.

The problem here is `readObject` of `Period` does not provide enough defensive copying. `in.readObject()` returns the reference of internal. 

Add the code to `Period` class

{% highlight java %}
private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
	s.defaultReadObject();

	// Defensively copy our mutable components
	start = new Date(start.getTime() );
	end = new Date(end. getTime() );

	// Check that our invariants are satisfied
	if (start.compareTo(end) > 0)
	throw new InvalidObjectException(start + " after " + end);	
}
{% endhighlight %}

To provide defensive copying of final field, we have to remove `final` keyword.

`readObject` method must implement all the validation that constructor does.

There are some rules for producing a more robust `readObject` method:

* For classes with object reference fields that must remain private, defensively copy each object in such a field.
* Check any invariants and throw an `InvalidObjectException` if a check fails. The checks should follow any defensive copying.
* If an entire object graph must be validated after it is deserialized, use the `ObjectInputValidation` interface.
* Do not invoke any overrideable methods in the class, directly or indirectly.

## 77. For instance control, prefer enum types to `readResolve` 

If we deserialize a Singleton instance, it will no longer be a Singleton, since deserialization creates another one.

`readResolve` allows you using `readObject` to create an object to replace another one. 

{% highlight java %}
class Single implements Serializable{
	public static Single getInstance() {
		return instance;
	}
	private static final Single instance = new Single("original");
	
	private String name = null;
	private Single(String name) { this.name = name; }
	private Single() {}
	
	public void setName(String name)
	{
		this.name = name;
	}
	
	@Override
	public String toString() {
		return name;
	}
	
	private Object readResolve() {
		System.out.println("read resolve called");
		return instance;
	}
}

public class SerialTest
{
	public static void main(String[] main)
	{
		try
		{
			Single s = Single.getInstance();
			
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.writeObject(s);
			
			ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()));
			Single res = (Single) (ois.readObject());
			
			res.setName("changed");
			
			System.out.println(s);
			System.out.println(res);
			
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
		catch (ClassNotFoundException e)
		{
			e.printStackTrace();
		}		
	}
}
{% endhighlight %}

This program output:

	read resolve called
	changed
	changed

Which means the deserialized object is actually the original one. Please compare the result after removing `readResolve()` method.

`readResolve` will return the original INSTANCE. If the object has reference field, they all should declared as `transient`. 

## 78. Consider serialization proxies instead of serialized instances 

__Serialization Proxy Pattern__ means, provide a private nested static class for a serializable class. This class is __serialization proxy__, it has a single constructor, and parameter is its enclosing class object. 

#### Example: Period class

{% highlight java %}
// Period class is from #76

// SerializationProxy is inside Period
private static class SerializationProxy implements Serializable{
	private final Date start;
	private final Date end;

	SerializationProxy(Period p) {
		this.start = p.start;
		this.end = p.end;
	}

	private Object readResolve() {
		return new Period(New Date(start.getTime()), new Date(end.getTime()));
	}

	private static final long serialVersionUID = ...;
}
{% endhighlight %}

Then, add these two methods to `Period`:

{% highlight java %}
private void readObject(ObjectInputStream stream) throw InvalidObjectException {
	throw new InvalidObjectException("Proxy required");
}

private Object writeReplace() {
	return new SerializationProxy(this);
}
{% endhighlight %}

When client serialize a `Period` object:

{% highlight java %}
// oos is a ObjectOutputStream
oos.writeObject(period)
{% endhighlight %}

Program goes into the `writeReplace()` of `Period`. It actually serializes a new `SerializationProxy` object. But the client doesn't know this. This new `SerializationProxy` object contains all the information of the `Period` object.

When client deserialize the `Period` object, which actually is `SerializationProxy` object:

{% highlight java %}
// ois is a ObjectInputStream
Period newPeriod = (Period)ois.readObject();
{% endhighlight %}

`ois` contains the `SerializationProxy` object. Program goes into the `readResolve()` of `SerializationProxy` object, which returns a copy of original `Period` object.

Now, client cannot call the `readObject` from `Period` directly.

__Serialization Proxy Pattern__ ensures `Period` is really immutable, the fields are `final`
