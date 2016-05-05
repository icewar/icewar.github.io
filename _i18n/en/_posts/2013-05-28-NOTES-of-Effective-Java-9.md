---
layout: post
title: Effective Java 9 - Concurrency
excerpt: 
tags: [java]

---

![](http://www.crazysmoove.com/memjug/javabooks-slides/images/Effective_Java.jpg)
<br />

* [66. Synchronize access to shared mutable data](#66.-synchronize-access-to-shared-mutable-data)
* [67. Avoid excessive synchronization](#67.-avoid-excessive-synchronization)
* [68. Prefer executors and tasks to threads](#68.-prefer-executors-and-tasks-to-threads)
* [69. Prefer concurrency utilities to wait and notify](#69.-prefer-concurrency-utilities-to-wait-and-notify)
* [70. Document thread safety](#70.-document-thread-safety)
* [71. Use lazy initialization judiciously](#71.-use-lazy-initialization-judiciously)
* [72. Don't depend on the thread scheduler](#72.-don't-depend-on-the-thread-scheduler)
* [73. Avoid thread groups](#73.-avoid-thread-groups)

* * *

> `synchronized` keyword makes sure that at the same time, there is only thread accessing all the synchronized methods in the object.

## 66. Synchronize access to shared mutable data 

The way to stop a thread interrupting another thread, the thread should poll a boolean field, which initialized with `false`, but the second thread can set it to `true`.

{% highlight java %}
public class StopThread {
	private static boolean stopRequested;

	public static void main(String[] args)
			throws InterruptedException {
		Thread backgroundThread = new Thread(new Runnable() {
			public void run() {
				int i = 0;
				while(!stopRequested)
					i++;
			}
		});
		backgroundThread.start();

		TimeUnit.SECONDS.sleep(1);
		stopRequested = true;
	}
}
{% endhighlight %}

Without `synchronize`, it is not guaranteed that backgoundThread sees the changed `stopRequested`. The VM will compile the `while` loop into:

{% highlight java %}
if (!done)
	while (true)
		i++;
{% endhighlight %}

This is an optimization called __Hoisting__.

When a new thread start, it will first read and load `stopRequested` from the main memory, which means the threads keeps a copy of `stopRequested` in the thread working memory. Until the thread finishes, it will only use the copy.

__Solution to this is:__

{% highlight java %}
public class StopThread {
	private static boolean stopRequested;

	private static synchronized void requestStop() {
		stopRequested = true;
	}

	private static synchronized boolean stopRequested() {
		return stopRequested;
	}

	public static void main(String[] args)
			throws InterruptedException {
		Thread backgroundThread = new Thread(new Runnable() {
			public void run() {
				int i = 0;
				while(!stopRequested)
					i++;
			}
		});
		backgroundThread.start();

		TimeUnit.SECONDS.sleep(1);
		requestStop();
	}
}
{% endhighlight %}

We synchronized both reading and writing. Only synchronize writing will not actually work.

__Another solution is__ to use `volatile` keyword. It means that the variable in the thread will not use the copy. It will be notified when the variable is updated.

{% highlight java %}
public class StopThread {
	private static volatile boolean stopRequested;

	public static void main(String[] args)
			throws InterruptedException {
		Thread backgroundThread = new Thread(new Runnable() {
			public void run() {
				int i = 0;
				while(!stopRequested)
					i++;
			}
		});
		backgroundThread.start();

		TimeUnit.SECONDS.sleep(1);
		stopRequested = true;
	}
}
{% endhighlight %}

But the purpose of `volatile` is to use the latest value. It does not guarantee synchronization. 

#### Example: generating sequential number

{% highlight java %}
private static volatile int nextNumber = 0;
public static int generateNumber() {
	return nextNumber++;
}
{% endhighlight %}

`++` operation on `nextNumber` is not atomic. This program may fail. 

One solution is to add `synchronized` to `generateNumber()`. 

Another way is to use Java API `java.util.concurrent.atomic.AtomicLong`. It is what we want, and it may perform better.

> __Limit variable data in a single thread. Some one calls your program may put it in a multiple threading environment.__


## 67. Avoid excessive synchronization 

This example uses composite-over-inheritance design to create an observer class.

{% highlight java %}
class ForwardingSet<E> implements Set<E> {
	private final Set<E> s;
	public ForwardingSet(Set<E> s) { this.s = s; }

	public void clear() { s.clear(); }
	public boolean contains(Object o) { return s.contains(o); }
	public boolean isEmpty() { return s.isEmpty(); }
	public int size() { return s.size(); }
	public Iterator<E> iterator() { return s.iterator(); }
	public boolean add(E e) { return s.add(e); }
	public boolean remove(Object o) { return s.remove(o); }
	public boolean containsAll(Collection< ? > c) { return s.containsAll(c); }
	public boolean addAll(Collection< ? extends E> c) { return s.addAll(c); }
	public boolean removeAll(Collection< ? > c) { return s.removeAll(c); }
	public boolean retainAll(Collection< ? > c) { return s.retainAll(c); }

	public Object[] toArray() { return s.toArray(); }
	public < T > T[] toArray(T[] a) { return s.toArray(a); }
	
	@Override
	public boolean equals(Object o) { return s.equals(o); }
	@Override public int hashCode() { return s.hashCode(); }
	@Override public String toString() { return s.toString(); }

	@Override
	public Iterator<E> iterator()
	{
		return null;
	}
}

interface SetObserver<E> {
	// Invoked when an element is added to the observable set
	void added(ObservableSet<E> set, E element);
}

public class ObservableSet<E> extends ForwardingSet<E> {
	public ObservableSet(Set<E> set) { super(set); }

	private final List< SetObserver<E> > observers = new ArrayList< SetObserver<E> >();

	public void addObserver(SetObserver<E> observer) {
		synchronized(observers) {
			observers.add(observer);
		}
	}

	public void removeObserver(SetObserver<E> observer) {
		synchronized(observers) {
			observers.remove(observer);
		}
	}

	private void notifyElementAdded(E element) {
		synchronized(observers) {
			for (SetObserver<E> observer : observers)
				observer.added(this, element);
		}
	}

	@Override
	public boolean add(E element) {
		boolean added = super.add(element);
		if (added) 
			notifyElementAdded(element);
		return added;
	}

	@Override
	public boolean addAll(Collection< ? extends E > c) {
		boolean result = false;
		for ( E element : c)
			result |= add(element);
		return result;
	}

	public static void main(String[] args) {
		ObservableSet<Integer> set = new ObservableSet<Integer>( new HashSet<Integer>() );
		
		set.addObserver(new SetObserver<Integer>() {
			public void added(ObservableSet<Integer> s, Integer e) {
				System.out.println(e);
			}
		});
		
		for (int i = 0; i < 100; i++)
			set.add(i);
	}
}
{% endhighlight %}

Currently this program works fine. It prints out the numbers from 0 to 99. 

If we change the observer in the `set`:

{% highlight java %}
set.addObserver(new SetObserver<Integer> () {
	public void added(ObservableSet<Integer> s, Integer e) {
		System.out.println(e);
		if (e == 23)
			s.removeObserver(this);
	}
}
{% endhighlight %}

We expect the program to end after printing 23. This will be illegal, since we are trying to delete an element from the set DURING we are iterating the set. `notifyElementAdded` is a synchronized block. 

#### Continue the example

Now we are trying to unsubscribe the observer using another thread.

{% highlight java %}
set.addObserver( new SetObserver<Integer> () {
	public void added(final ObservableSet<Integer> s, Integer e) {
		System.out.println(e);
		if (e == 23) {
			ExecutorService executor = Executors.newSingleThreadExecutor();
			final SetObserver<Integer> observer = this;
			try {
				executor.submit(new Runnable() {
					public void run() {
						s.removeObserver(observer);
					}
				}).get();
			}
			catch (ExecutionException ex) {
				throw new AssertionError(ex.getCause());
			}
			catch (InterruptedException ex) {
				throw new AssertionError(ex.getCause());
			} finally {
				executor.shutdown();
			}
		}
	}
});

set.addObserver(new SetObserver<Integer>() {
	public void added(ObservableSet<Integer> s, Integer e) {
		System.out.println(e);
		if ( e == 23 )
			s.removeObserver(this);
	}
});

...
		
{% endhighlight %}

`Executor` service is provided by `java.util.concurrent` package.

The new observer is added before the previous one. It encounters deadlock. Because in the main thread, `add()` calls `notifyElementAdded()`, the later locks `observers`. And the newly added observer also want to gain the lock.

Calling external method, a method from outside of the containing class, always causes deadlock. We can move the external method out of the synchronized block, by making a snapshot, and operate on the snapshot.

{% highlight java %}
private void notifyElementAdded(E element) {
	List<SetObserver<E>> snapshot = null;
	synchronized(observers) {
		snapshot = new ArrayList<SetObserver<E>>(observers);
	}
	for (SetObserver<E> observer : observers)
		observer.added(this, element);
}
{% endhighlight %}

A better way to move external method out of synchronized code block is by using __concurrent collection__ (since Java 1.5). This is a variant of `ArrayList`, does all the operations in a copy of the low level array. Therefore it does not require synchronization, and the performance is good. If the program changes the array a lot, the performance will not be good. But for the observer list here, it is very good.

{% highlight java %}
private final List< SetObserver<E> > observers = 
	new CopyOnWriteArrayList< SetObserver<E> >();

public void addObserver( SetObserver<E> observer) {
	observers.add(observer);
}

public boolean removeObserver(SetObserver<E> observer) {
	return observers.remove(observer);
}

private void notifyElementAdded(E element) {
	for (SetObserver<E> observer : observers)
		observer.added(this, element);
}
{% endhighlight %}

## 68. Prefer executors and tasks to threads 

__Executor__ is an interface-based task executor. To use it:

{% highlight java %}
ExecutorService executor = Executors.newSingleThreadExecutor();
executor.execute(runnable);
...
executor.shutdown();
{% endhighlight %}

If you want to use more than one thread to deal with a task queue, just use a executor service factory(which actually is a __thread pool__), or directly `ThreadPoolExecutor` class in Java.

For a small project, `Executors.newCachedThreadPool` is a good choice, but not for a big project. It may make the server overloaded. 

### Executor Framework

Previously, thread is both the working unit and the working mechanism. Now we need toe separate them. Working unit should be `Runnable` or `Callable`, `Runnable` returns value. Working mechanism is executor service. 

`ScheduledThreadPoolExecutor` in Executor Framework can replace `java.util.Timer`. 

Please refer to _Java Concurrency in Practice_ for more details on Executor Framework.

## 69. Prefer concurrency utilities to wait and notify 

From Java 1.5, `java.util.concurrent` has three kinds of tools: Executor Framework, Concurrent Collection and Synchronizer.

### Concurrent Collection

It provides high performance concurrency for traditional Collections like `List` and `Queue`. If you use concurrent collection, make sure you have concurrent job inside, otherwise you will only slow down your program.

`ConcurrentMap` extends from `Map`.

{% highlight java %}
private static final ConcurrentMap<String, String> map = 
	new ConcurrentHashMap<String, String>();

public static String intern(String s) {
	String previousValue = map.putIfAbsent(s, s);
	return previousValue == null ? s : previousValue;
}
{% endhighlight %}

`ConcurrentHashMap` is even better.

Prefer `ConcorrentHashMap` to `Collections.synchronizedMap` or `Hashtable`

Most of the `ExecutorService`s have implemented BlockingQueue. They will be blocked until operation finishes.

### Synchronizer

It makes thread waiting for another thread, and collaborate. Most common synchronizers are `CountDownLatch` and `Semaphore`.

`CountDown Latch` is a single-use barrier, makes threads waiting for other threads. 

#### Example: CountDown Latch

Suppose we have a batch of tasks, they need to start at the same time. Before they start, they need to get ready. Once all the tasks are ready, they start together, and a timer starts counting. Once last task finishes, the timer stops counting.

{% highlight java %}
// int concurrency is the concurrency level, means the number of times the countDown() has to be called
public static long time(Executor executor, int concurrency, final Runnable action) throws InterruptedException {
	final CountDownLatch ready = new CountDownLatch(concurrency);
	final CountDownLatch start = new CountDownLatch(concurrency);
	final CountDownLatch done = new CountDownLatch(concurrency);

	for (int i = 0; i < concurrency; i++) {
		executor.execute(new Runnable() {
			public void run() {
				ready.countDown();
				try {
					start.await();
					action.run();

				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				} finally {
					done.countDown();
				}
			}
		});
	}
	ready.await();
	long startNanos = System.nanoTime();
	start.countDown();
	done.await();
	return System.nanoTime() - startNanos;
}
{% endhighlight %}

`start.await()` means wait here, until the `start`. `done.await()` waits there, until it becomes 0, then return the running time.

__Use `System.nanoTime` instead of `System.currentTimeMills`__

## 70. Document thread safety 

A method documented with `@synchronized` does not mean that it is completely thread-safe.

There are several thread security levels:

* __Immutable__: the instance is immutable, no need external synchronization. eg. `String`, `Long`, `BigInteger`
* __Unconditionally thread-safe__: the instance can be changed, but it has sufficient internal synchronization that its instances can be used concurrently without the need for any external synchronization. eg. `Random` and `ConcurrentHashMap` 
* __Conditionally thread-safe__: some methods require external synchronization for safe concurrent use.
* __Not thread-safe__: instances are mutable. Client must surround each method invocation with external synchronization if the method will be used concurrently.
* __thread-hostile__: This class is not safe even if all method invocations are surrounded by external synchronization.

Thread-safe type should be documented. 

#### Private lock object

Private lock object can be an alternative of synchronized block.

{% highlight java %}
private final Object lock = new Object();

public void foo() {
	synchronized(lock) {

	}
}
{% endhighlight %}

Private lock object can only be applied to unconditional thread-safe. Because in conditional thread-safe method, you must document which lock the user has to gain.

## 71. Use lazy initialization judiciously 

Lazy initialization is an optimization technique. 

Lazy initialization should only be used when the initialization cost is high. 

If multiple threads are using a lazy-initialed object, you should be careful about the initialization.

A typical way to initialed an object:

{% highlight java %}
private final FieldType field - conputeFieldValue();
{% endhighlight %}

If we use lazy initialization, that part needs to be synchronized:

{% highlight java %}
private FieldType field;

synchronized FieldType getField() {
	if (field == null)
		field = computeFieldValue();
	return field;
}
{% endhighlight %}

If we need to lazy initiate a static field, we can use __lazy initialization holder class__.

{% highlight java %}
private static class FieldHolder {
	static final FieldType field = computerFieldValue();
}
static FieldType getField() { return FieldHolder.field; }
{% endhighlight %}

When `getField()` get called for the first time, it accesses `FieldHolder.field`, which makes `FieldHolder` class initialized. Later `getField()` will return the created object. The point is we don't need to add `synchronized` before `getField()`, and the code is safe.

## 72. Don't depend on the thread scheduler 

Any program that replies on the thread scheduler for correctness or performance is likely to be nonportable.

We'd better keep the average number of threads running to be less than the number of CPU cores. To achieve that, we need to make thread do more meaningful tasks. Meanwhile keep thread pool small. 

Don't make thread in a __busy-wait__ state, repeating checking the state of a shared object.

Don't use `Thread.yield` to gain more CPU time for a thread. This is nonportable. You should redesign the application and decrease the number of concurrent threads. `Thread.yield` should only be used in testing.

## 73. Avoid thread groups 

The __thread group__ that Java provided is very insecure.

Try to use thread pool executor instead.
