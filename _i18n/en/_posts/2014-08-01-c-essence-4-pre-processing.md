---
layout: post
title: C Essense (4) - Preprocessing
excerpt: C language pre-processing steps, macro syntax
cover_image: cppcafe.jpg
thumbnail: /images/blog/c-programmers-thumb.jpg
tags: [c]

---

* [1. Preprocessing steps](#1.-preprocessing-steps)
* [2. Macro definition](#2.-macro-definition)
	* [2.1 Function-like Macro](#2.1-function-like-macro)
	* [2.2 Inline function](#2.2-inline-function)
	* [2.3 `#`, `##` operator](#2.3-#,-##-operator)
	* [2.4 Macro expansion](#2.4-macro-expansion)
* [3. Conditional preprocessing](#3.-conditional-preprocessing)
* [4. Other thing about preprocessing](#4.-other-thing-about-preprocessing)

* * *

## 1. Preprocessing steps

This is how C compiler doing pre-processing

1. Windows platform uses `\r\n` as endline char, whereas Linux uses `\n`
2. Use `\` (__without space or other stuff behind__) to concatenate multiple lines
3. Comment is converted to a space
4. Tokenization
5. Parsing. Replace macro with source and repeat step 1-4 if macro appears.
6. escape char constants, eg. `\n` -> `0x0a`
7. concatenate consequtive strings.

__Example:__

	#define STR "hello, "\
					"world"

	printf(
		STR);

After tokenization, program becomes: `printf`, `(`, endline, TAB key, `STR`, `)`, `;`, endline.

After parsing, program becomes: `printf`, `(`, endline, TAB key, `"hello, world"`, `)`, `;`, endline.

8. remove empty string, and pass tokens to C parser

## 2. Macro definition

### 2.1 Function-like Macro

* __Object-like macro__: eg: `#define N 20`, `#define STR "hello, world"`
* __Function-link macro__: eg: `#define MAX(A, b) ((a)>(b)?(a):(b))`

When using a real `max(a,b)` function, all the function call will be compiled to instructions that passes arguments to that function, where macros will be compiled to execution instructions. Thus, normally, code using function-like macro will be compiled to bigger object file.

__NOTICE:__

1. the `()` surrounding parameters cannot be ignored.
2. Calculate argument value first, then call function-like macro. `MAX(++a, ++b)` will become `((++a)>(++b)?(++a):(++b))`, which leads to wrong result.
3. functino-like macro normally leads to low performance. But it does not require stack allocation and argument passing.

#### do ... while macro

In Linux kernel, `include/linux/pm.h`:

{% highlight c %}

#define device_init_wakeup(dev,val) \        do { \               device_can_wakeup(dev) = !!(val); \               device_set_wakeup_enable(dev,val); \        } while(0)

{% endhighlight %}
If we don't use `do .. while`:

{% highlight c %}

#define device_init_wakeup(dev,val) \               device_can_wakeup(dev) = !!(val); \               device_set_wakeup_enable(dev,val);

if (n > 0)
	device_init_wakeup(d,v);
{% endhighlight %}

After expansion, the second line is not included in `if` block.

Can we use `{ .. }`?
{% highlight c %}
#define device_init_wakeup(dev,val) \               { device_can_wakeup(dev) = !!(val); \               device_set_wakeup_enable(dev,val); }

if (n > 0)
	device_init_wakeup(d,v);
{% endhighlight %}
The problem is the `;` at the end of `device_init_wakeup(d,v);`. Without `;`, it does not look like function call. With `;`, the syntax is wrong. It becomes `{ .. };`.

Using `do { ... } while (0)` is a good solution.#### Duplicate macro definition

Duplicated macro definition must be exactly the same.
These two are allowed at the same time:

{% highlight ruby %}
#define OBJ_LIKE (1 - 1)
#define OBJ_LIKE (1/* comment */-/* comment */ 1)/*
comment */
{% endhighlight %}
Comments will be removed.

But these two are different:

{% highlight c %}
#define OBJ_LIKE (1 - 1)
#define OBJ_LIKE (1-1)
{% endhighlight %}

You can use `#undef` to cancel a definition.

### 2.2 Inline function

`inline` keyword tells compiler

{% highlight c %}
inline int MAX(int a, int b)
{
    return a > b ? a : b;
}

int a[] = { 9 , 3 , 5 , 2 , 1 , 0 , 8 , 7 , 6 , 4 };

int max(int n)
{
    return n == 0 ? a[0] : MAX(a[n], max(n-1));
}

int main() {
    max(9);
    return 0;
}
{% endhighlight %}Compile it:
{% highlight sh %}
$ gcc main.c -g
$ objdump -dS a.out
{% endhighlight %}	int max(int n)
	{
	  4004ca:	55                   	push   %rbp
	  4004cb:	48 89 e5             	mov    %rsp,%rbp
	  4004ce:	48 83 ec 10          	sub    $0x10,%rsp
	  4004d2:	89 7d fc             	mov    %edi,-0x4(%rbp)
	    return n == 0 ? a[0] : MAX(a[n], max(n-1));
	  4004d5:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
	  4004d9:	75 08                	jne    4004e3 <max+0x19>
	  4004db:	8b 05 5f 0b 20 00    	mov    0x200b5f(%rip),%eax        # 601040 <a>
	  4004e1:	eb 24                	jmp    400507 <max+0x3d>
	  4004e3:	8b 45 fc             	mov    -0x4(%rbp),%eax
	  4004e6:	83 e8 01             	sub    $0x1,%eax
	  4004e9:	89 c7                	mov    %eax,%edi
	  4004eb:	e8 da ff ff ff       	callq  4004ca <max>
	  4004f0:	89 c2                	mov    %eax,%edx
	  4004f2:	8b 45 fc             	mov    -0x4(%rbp),%eax
	  4004f5:	48 98                	cltq
	  4004f7:	8b 04 85 40 10 60 00 	mov    0x601040(,%rax,4),%eax
	  4004fe:	89 d6                	mov    %edx,%esi
	  400500:	89 c7                	mov    %eax,%edi
	  400502:	e8 ad ff ff ff       	callq  4004b4 <MAX>
	}
	  400507:	c9                   	leaveq
	  400508:	c3                   	retq`MAX` is compiled as normal function. If we set optimization level:
{% highlight sh %}
$ gcc main.c -g -O
$ objdump -dS a.out
{% endhighlight %}	int max(int n)
	{
	  4004bc:	53                   	push   %rbx
	  4004bd:	89 fb                	mov    %edi,%ebx
	    return n == 0 ? a[0] : MAX(a[n], max(n-1));
	  4004bf:	8b 05 7b 0b 20 00    	mov    0x200b7b(%rip),%eax        # 601040 <a>
	  4004c5:	85 ff                	test   %edi,%edi
	  4004c7:	74 17                	je     4004e0 <max+0x24>
	  4004c9:	8d 7b ff             	lea    -0x1(%rbx),%edi
	  4004cc:	e8 eb ff ff ff       	callq  4004bc <max>
	  4004d1:	48 63 db             	movslq %ebx,%rbx
	inline int MAX(int a, int b)
	{
	    return a > b ? a : b;
	  4004d4:	8b 14 9d 40 10 60 00 	mov    0x601040(,%rbx,4),%edx
	  4004db:	39 d0                	cmp    %edx,%eax
	  4004dd:	0f 4c c2             	cmovl  %edx,%eax
	int a[] = { 9 , 3 , 5 , 2 , 1 , 0 , 8 , 7 , 6 , 4 };

	int max(int n)
	{
	    return n == 0 ? a[0] : MAX(a[n], max(n-1));
	}
	  4004e0:	5b                   	pop    %rbx
	  4004e1:	c3                   	retq

`MAX()` function is inlined in `max()`

### 2.3 `#`, `##` operator

In macro definition, `#` operator is used to create string.

{% highlight c %}
#define STR(s) # s
STR(hello		world)
{% endhighlight %}

After compilation, `STR(hello 	world)` becomes `"hello world"`. Redundant spaces are removed.

{% highlight c %}
#define STR(s) #sfputs(STR(strncmp("ab\"c\0d", "abc", '\4"')		== 0) STR(: @\n), s);
{% endhighlight %}

The compiled program is `fputs("strncmp(\"ab\\\"c\\0d\", \"abc\", '\\4\"') == 0" ": @\n", s);`.

__NOTICE__:

* `"` becomes `\"`
* `\` becomes `\\`
* `"` becomes `\"`

`##` concatenate two tokens into one.

{% highlight c %}
#define CONCAT(a,b) a##b
CONCAT(con, cat)
{% endhighlight %}

Compiled to `concat`

{% highlight c %}
#define HASH_HASH # ## #
{% endhighlight %}

The value of this is `##`, because the `##` in the middle concat two `#`s. The space cannot be ignored.

#### vargs

{% highlight c %}
#define showlist(...) printf(#__VA_ARGS__) #define report(test, ...) ((test)?printf(#test):\printf(__VA_ARGS__))
showlist(The first, second, and third items.); report(x>y, "x is %d but y is %d", x, y);
{% endhighlight %}

After preprocessing:

{% highlight c %}
￼￼￼￼￼printf("The first, second, and third items."); ((x>y)?printf("x>y"): printf("x is %d but y is %d", x, y));
{% endhighlight %}

### 2.4 Macro expansion

An example:

{% highlight c %}
#define sh(x) printf("n" #x "=%d, or %d\n",n##x,alt[x]) #define sub_z 26sh(sub_z)
{% endhighlight %}

1. Since `sh(x)` contains `#x`, `x`=`sub_z`, thus `#x` = `"sub_z"`.
2. `n##x` = `nsub_z`
3. all the `#` and `##` operator are processes, now substitue `sub_z` to 26, thus `x` = 26
4. it becomes `printf("n" "sub_z" "=%d, or %d\n",nsub_z,alt[26])`

## 3. Conditional preprocessing

__Header Guard__:

{% highlight c %}
#ifndef HEADER_FILENAME#define HEADER_FILENAME/* body of header */#endif
{% endhighlight %}

It always be used to system configuration

{% highlight c %}
￼￼#if MACHINE == 68000    int x;#elif MACHINE == 8086 long x;#else /* all others */#error UNKNOWN TARGET MACHINE#endif
{% endhighlight %}

Linux system config is in `include/linux/config.h`

#### `#if`

{% highlight c %}
#define VERSION 2#if defined x || y || VERSION < 3
{% endhighlight %}

`defined` is a operator. Here, if x is defined, then `defined x` is `1`, else it is `0`. The whole macro becomes `#if 0 || y || 2<3`

If `y` has a value, then replace it. Else `y` is `0`, then the whole macro is `#if 0 || 0 || 2<3`, which is `#if 1`, which is true.

## 4. Other thing about preprocessing

`#pragma` is followed by compiler-defined macro.

C language has some special macros.

* `__FILE__`: current file name
* `__LINE__`: current line number

Here is a piece of code from `assert.h`

{% highlight c %}
/* assert.h standard header */#undef assert /* remove existing definition */#ifdef NDEBUG#define assert(test) ((void)0)#else        /* NDEBUG not defined */void _Assert(char *);/* macros */#define _STR(x) _VAL(x)#define _VAL(x) #x#define assert(test) ((test) ? (void)0 \" #test))#endif
{% endhighlight %}

Another thing is `__func__`, which is a function introduced in C99. It returns a string that is a current function name.
