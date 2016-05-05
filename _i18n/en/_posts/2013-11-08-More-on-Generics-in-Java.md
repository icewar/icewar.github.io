---
layout: post

title: More on Generics in Java
cover_image: blog-cover.jpg
excerpt: 
tags: [java]

---

### How to define a subclass of a generic class?

Wrong: `public class A extends Apple<T>`.

Correct: `public class A extends Apple<String>` or `public class A extends Apple` (will have a warning).

### What is the class of `ArrayList<String>`?

Try this:

{% highlight java %}

List<String> l1 = new ArrayList<String>();
List<Integer> l2 = new ArrayList<Integer>();

System.out.println( l1.getClass() == l2.getClass() );

{% endhighlight %}


Which means Java does not create a new type for `ArrayList<String>`. Thus, we cannot check generic type using `instanceof`.

