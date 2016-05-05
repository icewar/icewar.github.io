---
layout: post
title: C Essense (5) - Makefile
excerpt:
cover_image: blog/c-programmers.jpg
thumbnail: /images/blog/c-programmers-thumb.jpg
tags: [c]

---

* [1. Basic Rule](#1.-basic-rule)
* [2. Implicit rule & Pattern rule](#2.-implicit-rule-&-pattern-rule)
* [3. Variables](#3.-variables)
* [4. Header file dependencies](#4.-header-file-dependencies)
* [5. `make` command options](#5.-make-command-options)

* * *

## 1. Basic Rule

Suppose we have a project, structure is like this:

	.
	├── main.c
	├── main.h
	├── maze.c
	├── maze.h
	├── stach.h
	└── stack.c

`stack` is our self-implemented stack, and `maze` is a maze game.

To compile them together, I can run `gcc main.c stack.c maze.c -o main`.

If I modify `maze.c`, then I need to re-compile all the files.

It's better to do it this way:

{% highlight sh %}
￼$ gcc -c main.c
$ gcc -c stack.c
$ gcc -c maze.c
$ gcc main.o stack.o maze.o -o main
{% endhighlight %}

Then if I modified `maze.c`, the only thing I need to do is:

{% highlight sh %}
$ gcc -c maze.c
$ gcc main.o stack.o maze.o -o main
{% endhighlight %}

__To avoid typo__, we can create a `Makefile`:

{% highlight make %}
main: main.o stack.o maze.o
	gcc main.o stack.o maze.o -o main

main.o: main.c main.h stack.h maze.h
	gcc -c main.c

stack.o: stack.c stack.h main.h
	gcc -c stack.c

maze.o: maze.c maze.h main.h
	gcc -c maze.c
{% endhighlight %}


The format of `makefile` rule is:

	target ... : prerequisites ...
		command1
		command2
		...

The first rule in `makefile` is the default rule.

For every command start with Tab in `makefile`, `make` will create a Shell process to execute it.

`make` will only recompile the target that is modified, by checking the last modified time of source file `.c` `.h`, and target file `.o`.

To Summarize, target needs to be updated if one of the criteria is meet:

* target has not been run.
* one of the prerequisites needs to be updated
* some prerequisites's last modified time is later than current target

Normally Makefile will have a `clean` target:

{% highlight make %}
clean:
	@echo "cleanning project"
	-rm main *.o
	@echo "clean completed"
{% endhighlight %}

So we can run `make clean`. `@` means does not display command itself, and only display the result. By default if one command fails, the target is terminated. `-` means even if command fails, the target should continue.

There is a list of special built-in target, like `.PHONY`. Check this link about [GNU Special Targets](https://www.gnu.org/software/make/manual/html_node/Special-Targets.html)

`GNUMake` also has some common target, that normally we follow the convention:

* `all`: default target
* `install`
* `clean`: clean the generated binary files
* `distclean`

The name of makefile is not required to be `Makefile`, but it is recommended. The order of looking for makefile is `GNUmakefile` -> `makefile` -> `Makefile`.

## 2. Implicit rule & Pattern rule


One rule can be written in multiple sub-rules, but only one rule should have the commands.

{% highlight make %}
main.o: main.h stack.h maze.h

main.o: main.c
	gcc -c main.c
{% endhighlight %}


Example in first section can be written as:

{% highlight make %}
main: main.o stack.o maze.o
	gcc main.o stack.o maze.o -o main

main.o: main.h stack.h maze.h

stack.o: stack.h main.h

maze.o: maze.h main.h

main.o: main.c
	gcc -c main.c

stack.o: stack.c
	gcc -c stack.c

maze.o: maze.c
	gcc -c maze.c

clean:
	-rm main *.o

.PHONY: clean
{% endhighlight %}

There are some rules that can be omitted:

{% highlight make %}
main: main.o stack.o maze.o
	gcc main.o stack.o maze.o -o main

main.o: main.h stack.h maze.h

stack.o: stack.h main.h

maze.o: maze.h main.h

clean:
	-rm main *.o

.PHONY: clean
{% endhighlight %}

When we run `make`:

	$ make
	cc -c -o main.o main.c
	cc -c -o stack.o stack.c
	cc -c -o maze.o maze.c
	gcc main.o stack.o maze.o -o main

If all the prerequisites of a target do not have command list, then `make` will try built-in __implicit rule__. Use `make -p` to list all implicit rules.

In the example, we have used:

{% highlight make %}
# default
OUTPUT_OPTION = -o $@

# default
CC = cc

# default
COMPILE.c = $(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c

%.o: %.c
# commands to execute (built-in):
        $(COMPILE.c) $(OUTPUT_OPTION) $<
{% endhighlight %}


`CC` is a makefile variable. `CC=cc` is the declaration, and `$(CC)` gets its value. `cc` points to the C compiler. It could be `gcc` or `clang` depends on your system. `CFLAGS`, `CPPFLAGS`, `TARGET_ARCH` here are all empty. `COMPILE.c` command becomes `cc -c`.

`$@` fetches the target in the rule, and `$<` fetches the first prerequisites.

`%.o: %.c` is a pattern rule. `main.o` matches this `%.o` pattern, so `%`=`main`. Thus it will run `cc -c -o main.o main.c`.

`stack.o` and `maze.o` also match `%.o` target.

For multiple target rule:

	target1 target2: prerequisite1 prerequisite2 command $&lt; -o $@

It becomes:

	target1: prerequisite1 prerequisite2
		command prerequisite1 -o target1
	target2: prerequisite1 prerequisite2
		command prerequisite1 -o target2

## 3. Variables

In makefile, variable declaration can be put behind calling.

{% highlight make %}
main.o: main.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<
CC = gcc
CFLAGS = -O -g
CPPFLAGS = -Iinclude
{% endhighlight %}

Expanded command is `gcc -O -g -Iinclude -c main.c`.

* `CFLAGS`: compilation options, like `-O`, `-g`.
* `CPPFLAGS`: preprocessing options, like `-D`, `-I`.

When declaration is behind calling, it is easy to write calling cycle, like this:

	A = $(B)
	B = $(A)

* * *

An example:

{% highlight make %}
foo = $(bar)
bar = Huh?
all:
	@echo $(foo)
{% endhighlight %}


The value of `foo` is determined in `all:`, not at line 1.

* * *

If you want variable to be evaluated immediately, use `:=`.

Another example:

	y := $(x) bar
	x := foo

`y` will be evaluated as `bar` since `x` is empty string at the time of evaluating.

Operator `?=` means, only assign value if it has not been assigned. It is like `||=` in Ruby.

`+=` is also allowed in makefile.

Other special variables:

* `$?`: all the prerequisite that needs to be updated in a rule, as a list
* `$^`: all the prerequisite, as a list

	main: main.o stack.o maze.o
		gcc main.o stack.o maze.o -o main

can be writter as:

{% highlight make %}
main: main.o stack.o maze.o
	gcc $^ -o $@
{% endhighlight %}

* * *

{% highlight make %}
libsome.a: foo.o bar.o lose.o win.o
		ar r libsome.a $?
       ranlib libsome.a
{% endhighlight %}

This is for build library file. `ar` is a archive tool.

* * *

Some frequently used makefile variables:

Variable Name | Default value | Description
--- | --- | ---
`AR` | `ar` | archive tool
`ARFLAGS`|
`AS` | `as` | assembly compiler
`ASFLAGS`|
`CC`|
`CFLAGS` |
`CXX` | `g++` | C++ compiler name
`CXXFLAGS` |
`CPP` | `$(CC) -E` | C preprocessor name
`CPPFLAGS` |
`LD` | `ld` | linker name
`LDFLAGS` |
`TARGET_ARCH` | | target platform options
`OUTPUT_OPTION` | `-o $@` |
`LINK.o` | `$(CC) $(LDFLAGS) $(TARGET_ARCH)` | link `.o` files.
`LINK.c` | `$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH)`| link `.c` files
`LINK.cc` | `(CXX) $(CXXFLAGS)
$(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH)` | link `.cc` files, which are cpp files.
`COMPILE.c` | `$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c` | compile c files
`COMPILE.cc` | `$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c` | compile cc files
`RM` | `rm -f` | remove command

## 4. Header file dependencies

Our makefile looks like this now:

```
all: main
main: main.o stack.o maze.o gcc $^ -o $@
main.o: main.h stack.h maze.h
stack.o: stack.h main.h
maze.o: maze.h main.h
clean:
	-rm main *.o
.PHONY: clean
```

One problem is that, we need to check the source code to determine header files dependencies. If we update source file, we may forget to update makefile.

`gcc -M` auto generate target file and source file dependencies:

	$ gcc -M main.c
	main.o: main.c /usr/include/stdio.h /usr/include/features.h \
	/usr/include/sys/cdefs.h /usr/include/bits/wordsize.h \ /usr/include/gnu/stubs.h /usr/include/gnu/stubs-32.h \ /usr/lib/gcc/i486-linux-gnu/4.3.2/include/stddef.h \ /usr/include/bits/types.h /usr/include/bits/typesizes.h \ /usr/include/libio.h /usr/include/_G_config.h
	/usr/include/wchar.h \ /usr/lib/gcc/i486-linux-gnu/4.3.2/include/stdarg.h \ /usr/include/bits/stdio_lim.h /usr/include/bits/sys_errlist.h
	main.h \
	  stack.h maze.h

If we don't want system header file dependencies, use `-MM`:

	$ gcc -MM *.c
	main.o: main.c main.h stack.h maze.h maze.o: maze.c maze.h main.h stack.o: stack.c stack.h main.h

Next problem is, how to put the dependencies into makefile:

{% highlight make %}
sources = main.c stack.c maze.c
include $(sources:.c=.d)
%.d: %.c
	set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$
{% endhighlight %}

`$(sources:.c=.d)` is a substitution syntax, which means substitute all the `.c` to `.d` in `sources`. `include $(sources:.c=.d)` becomes:

    include main.d stack.d maze.d

`include` means read other makefiles.

You don't have `.d` files for now, so `make` tries the pattern rule `%.d: %.c`. The four lines below, uses only one make process to run it. `set -e` means, in current process, if any of the command returns non-zero, the process terminates. `rm -f $@` removes previous generated `.d` file. `$$` is the process id. We use `sed` tool to generate `.d` makefiles.

## 5. `make` command options

* `-n` print the compiled command, but not execute it.
* `-C` is used change directory and run a makefile there.
