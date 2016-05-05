---
layout: post
title: Virtual in C++
excerpt:
cover_image: cppcafe.jpg
tags: [c++]

---

I have a program to explain the __static typing__ and __dynamic typing__ in C++.

{% highlight cpp %}
#include <iostream>
using namespace std;

class A {
public:
    A () {}
    void bark()
    {
        cout << "this is A" << endl;
    }
};

class B: public A
{
public:
    B () {}
    void bark()
    {
        cout << "this is B" << endl;
    }
};

int main(void)
{
    B b;
    A *a = &b;
    a->bark();
    
    return 0;
}
{% endhighlight %}

This program outputs `this is A`. If you are a Java programmer, you might thihk this should be `this is B`. But it is not.

`bark()` in `A` is static typing now, which means `a`'s type is always `A`. `a` does not know `B`.

To make it barking `this is B`, it's easy. Add `virtual` before the `void bark()` in `A`.

`virtual` makes `bark()` be called based on the real type, which might be the subclass of `A`, which is `B` here.
