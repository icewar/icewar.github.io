---
layout: post
title: Effective Java 5 - Enums and Annotations
excerpt:
tags: [java]
---

![1](http://www.crazysmoove.com/memjug/javabooks-slides/images/Effective_Java.jpg)
<br />

* [30. Use enums instead of `int` constants](#30.-use-enums-instead-of-int-constants)
* [31. Use instance fields instead of ordinals](#31.-use-instance-fields-instead-of-ordinals)
* [32. Use `EnumSet` instead of bit fields](#32.-use-enumset-instead-of-bit-fields)
* [33. Use `EnumMap` instead of ordinal indexing](#33.-use-enummap-instead-of-ordinal-indexing)
* [34. Emulate extensible enums with interfaces](#34.-emulate-extensible-enums-with-interfaces)
* [35. Prefer annotation to naming patterns(naming convention)](#id="35.-prefer-annotation-to-naming-patterns(naming-convention)")
* [36. Consistenly use the `Override` annotation](#36.-consistenly-use-the-override-annotation)
* [37. Use marker interfaces to define types](#37.-use-marker-interfaces-to-define-types)

* * *

## 30. Use enums instead of `int` constants 

{% highlight java %}
public enum Apple { FUJI, PIPPIN, GRANNY_SMITH };
{% endhighlight %}

#### Adding methods to enum

{% highlight java %}
public enum Sample {
	Obj1 (1.0, 2.0),
	Obj2 (3.0, 4.0),
	Obj3 (5.0, 6.0);

	private final double a;
	private final double b;
	private final double c = 2.3;
	private final double d;


	// constructor
	Sample(double a, double b) {
		this.a = a;
		this.b = b;
		this.d = a*c-b;
	}

	public double a() { return a; }
	public double b() { return b; }
	public double d() { return d; }


}
{% endhighlight %}

__Pay attention__ to the sign after `Obj1` and `Obj3`. One is `,`, the other is `;`.

{% highlight java %}
public enum Operation {
	PLUS, MINUS, TIMES, DIVIDE;

	double apply(double x, double y) {
		switch(this) {
			case PLUS: return x + y;
			case MINUS: return x - y;
			case TIMES: return x * y;
			case DIVIDE: return x / y;
			default: throw new AssertionError("Unknown op: " + this);
		}
	}
}

{% endhighlight %}

`this` here refers to the enum value.

This piece of code, if we add a new operation, we need to modify `apply()`. It's not flexible.

{% highlight java %}
public enum Operation {
	PLUS("+") { double apply(double x, double y) { return x + y ; } },
	MINUS("-") { double apply(double x, double y) { return x - y ; } },
	TIMES("*") { double apply(double x, double y) { return x * y ; } },
	DIVIDE("/") { double apply(double x, double y) { return x / y ; } };

	private final String symbol;

	Operation(String symbol) { this.symbol = symbol; }

	@Override
	public String toString() { return symbol; }

	abstract double apply(double x, double y);
}
{% endhighlight %}

The `abstract` method in enum must be implemented by enum value.

Another good trick is, since we have a `toString()` method here, we can have a reverse operation for it called `fromString()`. `PLUS.toString()` returns `+`, so `Operation.fromString("+")` should return `PLUS`.

{% highlight java %}

private static final Map<String, Operation> stringToEnum = new HashMap<String, Operation>();

static {
	for (Operation op : values() )
		stringToEnum.put(op.toString(), op);
}

public static Operation fromString(String symbol) {
	return stringToEnum.get(symbol);
}

{% endhighlight %}

__Pay attention__, THE ORDER of `static` block and the method MATTERS here.

#### Strategy Design Pattern using enum

Here is a program counting the payroll. The payroll is different for weekdays and weekends.

The policy is:

* If work on weekday and worked less than 8 hours, then will be paid `hours*payRate`.
* If work on weekday and more than 8 hours, then wiil be paid `8*payRate + (hours - 8)*payRate / 2`
* If work on weekend, then will be paid `hours*payRate/2`

{% highlight java %}
enum PayrollDay {
	MONDAY(PayType.WEEKDAY),
	TUESDAY(PayType.WEEKDAY),
	WEDNESDAY(PayType.WEEKDAY),
	THURSDAY(PayType.WEEKDAY),
	FRIDAY(PayType.WEEKDAY),
	SATURDAY(PayType.WEEKEND),
	SUNDAY(PayType.WEEKEND);

	private final PayType;
	PayrollDay(PayType payType) { this.payType = payType; }

	double pay(double hoursWorked, double payRate) {
		return payType.pay(hoursWorked, payRate);
	}
	
	private enum PayType {
		WEEKDAY {
			double overtimePay(double hours, double payRate) {
				return hours <= HOURS_PER_SHIFT ? 0 : (hours - HOURS_PER_SHIFT) * payRate / 2;
			}
		},
		WEEKEND {
			double overtimePay(double hours, double payRate) {
				return hours * payRate / 2;
			}
		};

		private static final int HOURS_PER_SHIFT = 8;

		abstract double overtimePay(double hours, double payRate);

		double pay(double hoursWorked, double payRate) {
			double basePay = hoursWorked * payRate;
			return basePay + overtimePay(hoursWorked, payRate);
		}
	}
}

{% endhighlight %}

`PayrollDay` has certain `PayType`, `PayType` has a method `pay()`, each `PayType` has its own `overtimePay()`.

## 31. Use instance fields instead of ordinals 

Never derive a value associated with an enum from its ordinal; store it in an instance field instead.

{% highlight java %}
public enum Ensemble {
	SOLO(1), DUET(2), TRIO(3), QUARTET(4);

	private final int numberOfMusicians;
	Ensemble(int size) { this,numberOfMusicians = size; }
	public int numberOfMusicians() { return numberOfMusicians; }
}
{% endhighlight %}

## 32. Use `EnumSet` instead of bit fields 

When using bit fields:

{% highlight java %}
public class Text {
	public static final int STYLE_BOLD = 1 << 0;
	public static final int STYLE_BOLD = 1 << 1;
	public static final int STYLE_BOLD = 1 << 2;
	public static final int STYLE_BOLD = 1 << 3;

	public void applyStyles() { ... }

}

text.applyStyles(STYLE_BOLD | STYLE_ITALIC);
{% endhighlight %}

Try to use `EnumSet`

{% highlight java %}
public class Text {
	public enum Style { BOLD, ITALIC, UNDERLINE, STRIKETHROUGH }

	public void applyStyles(Set< Style > styles) { .. }
}

text.applyStyles(EnumSet.of(Style.BOLD, Style.ITALIC) );
{% endhighlight %}

## 33. Use `EnumMap` instead of ordinal indexing 

DON'T USE `ordinal()` in enum.

{% highlight java %}
public class Herb {
	public enum Type { A, B, C }

	private final String name;
	private final Type type;

	Berb(String name, Type type ) {
		this.name = name;
		this.type = type;
	}

	@Override
	public String toString() {
		return name;
	}
}

// Then we have some herbs

Herb[] garden = ...;

Set< Herb >[] herbsByType = (Set< Herb >[]) new Set[Herb.Type.values().length];
for (int i = 0; i < herbsByType.length; i++)
	herbsByType[i] = new HashSet< Herb >();

for (Herb h : garden)
	herbsByType[ h.type.ordinal() ].add(h); // DON'T USE ordinal()
{% endhighlight %}

Using array with generic is unsafe. Better way to do this is is to use `EnumMap`:

{% highlight java %}
Map< Herb.Type, Set< Herb > > herbsByType = new EnumMap< Herb.Type, Set< Herb > >(Herb.Type.class);

for (Herb.Type t : Herb.Type.values() )
	herbsByType.put(t, new HashSet< Herb >() );
for (Herb h : garden)
	herbsByType.get(h.type).add(h);

{% endhighlight %}

## 34. Emulate extensible enums with interfaces 

Sometimes we want to make enum like class, have inheritance. Take the `Operation` enum in [#30](#i30) as an example.

{% highlight java %}
public interface Operation { 
	double apply(double x, double y);
}

public enum BasicOperation implements Operation {
	PLUS("+") { public double apply(double x, double y) { return x + y; } },
	MINUS("-") { public double apply(double x, double y) { return x - y; } },
	TIMES("*") { public double apply(double x, double y) { return x * y; } },
	DIVIDE("/") { public double apply(double x, double y) { return x / y; } };
	
	private final String symbol;

	BasicOperation(String symbol) { this.symbol = symbol; }

	@Override
	public String toString() {
		return symbol;
	}

}

// Extend from BasicOperation

public enum ExtendedOperation implements Operation {
	EXP("^") { public double apply(double x, double y) { return Math.pow(x, y); } },
	REMAINDER("%") { public double apply(double x, double y) { return x % y; } };

	private final String symbol;

	ExtendedOperation(String symbol) { this.symbol = symbol; }

	@Override
	public String toString() {
		return symbol;
	}
}

public static void main(String[] args )
{
	double x = 1.1;
	double y = 2.2;

	test(ExtendedOperation.class, x, y);
}

private static <T extends Enum< T > & Operation > void test( Class< T > opSet, double x, double y) {
	for (Operation op : opSet.getEnumConstants())
		System.out.printf("%f %s %f = %f\n", x, op, y, op.apply(x, y) );
}

{% endhighlight %}

This will output `^` and `%` operation result.

We use interface and implement the interface with enum to extends enum.

## 35. Prefer annotation to naming patterns(naming convention) 

Naming convention in Java has several disadvantages:

1. Typo leads to error
2. There is no way to ensure that they are used only on appropriate program elements.
3. They provide no good way to associate parameter values with progarm elements.

#### Example: marker annotation

{% highlight java linenos %}
@Retention(RetentionPolicy.RUNTIME) // Test annotations should be retained at runtime
@Target(ElementType.METHOD) // Test annotation is legal only on method declarations
public @interface Test {	
}	
public class Sample {
  @Test 
  public static void m1() {} // test should pass
  public static void m2() {}			
  @Test
  public static void m3() {
	 thorw new RuntimeException("Boom"); // test should fail
  }
}
{% endhighlight %}

`Test` annotation only provides information for use by interested programs. For testing frameworks, they may use the annotations:

{% highlight java %}
public class RunTests {
	public static void main(String args[]) throw Exception {
		int tests = 0;
		int passed = 0;

		Class testClass = Class.forName(args[0]);
		for (Method m : testClass.getDeclaredMethods() ) {
			if (m.isAnnotationPresent(Test.class)) {
				tests++;
				try {
					m.invoke(null);
					passed++;
				}
				catch (InvocationTargetException wrappedExc) {
					Throwable exc = wrappedExc.getCause();
					System.out.println(m + " failed: " + exc);
				}
				catch (Exception exc) {
					System.out.println("INVALID @Test: " + m);
				}			
			}
		}
		System.out.printf("Passed: %d, Failed: %d%n", passed, tests - passed); 
	}
}
{% endhighlight %}

This program checked `isAnnotationPresent(Test.class)`, to perform certain job.

## 36. Consistenly use the `Override` annotation 

Avoid making mistakes.

## 37. Use marker interfaces to define types 

__Marker interface__ is the interface like `Serializable`.

Marker interfaces has some advantages over annotation:

#### 1. marker interfaces define a type that is implemented by instances of the marked class, while marker annotations do not.

This allows you to get some programming error in compilation time.

A bad thing in Java API is, the creator of `ObjectOutputStream` didn't use `Serializable` in `writeObject(Object obj)` method. The parameter should be `Serializable`.

#### 2. marker interfaces can be targeted more precisely.

Annoation may be applied to any type, wilhe interface may have some restriction.

`Set` interface can be applied to only subclass of `Collection` 

#### 3. It is possible to add more information to an annotation type after it is already in use, by adding one or more annotation type elements with defaults.

#### 4. They are part of the larger annotation facility.

### When to use annotation or marker interface?

If marking an element inside the class, then we can only use annotation. I marking a class, one interface can implement the functionality of many annotations. 

If you want to define a type here, use interface.

