---
layout: post
title: C Essense (2) - C and Assembly
excerpt:
cover_image: cppcafe.jpg
tags: [c]

---

> The source code was tested and passed in [CentOS 6.4 vagrant box](http://developer.nrel.gov/downloads/vagrant-boxes/CentOS-6.4-x86_64-v20130309.box)
> Github repository: [http://github.com/allenlsy/c_essence](http://github.com/allenlsy/c_essence)

* <a href="#1.-main()-and-startup-routine">1. `main()` and startup routine</a>
* [2. Storage layout of variables](#2.-storage-layout-of-variables)
* [3. C inlines assembly](#3.-c-inlines-assembly)

* * *

## 1. `main()` and startup routine 

The command `gcc main.c -o main`, it actually can be done in three separate steps:

1. `gcc -S main.c`: compile `main.c` to assembly code `main.s`
2. `gcc -c main.s`: compile `main.s` to target file `main.o`
3. `gcc main.o`: compile `main.o` to executable file `a.out`

![](/images/blog/cessense/pic11.png)

In _C Essence (1)_, the first assembly program, we compile and link the program by:

{% highlight sh %}
as hello.s -o hello.o
ld hello.o -o hello
{% endhighlight %}

If we link `hello.o` using `gcc`:

    $ gcc hello.o -o hello

    hello.o: In function `_start':
    (.text+0x0): multiple definition of `_start'
    /usr/lib/gcc/x86_64-redhat-linux/4.4.7/../../../../lib64/crt1.o:(.text+0x0): first defined here
    /usr/lib/gcc/x86_64-redhat-linux/4.4.7/../../../../lib64/crt1.o: In function `_start':
    (.text+0x20): undefined reference to `main'
    collect2: ld returned 1 exit status

There are two errors: 

1. multiple definitions of `_start`: one is from the assembly code, the other is from `/sr/lib/crt1.o`.
2. `_start` in `crt1.o` need `main()`, and we don't have `main()` in the assembly code

From here we can see, `gcc` actually call `ld` to link `crt1.o` and `hello.o`. `crt1.o` has a `_start` entry point, we should not implement it ourselves if we want to use `gcc` to link. And `_start` need `main()`.

`_start` will do some startup routine, and then call `main()` to do the real job. __Therefore, the real entry point of a C program is `_start` rather than `main()`__

#### Another example

{% highlight cpp %}
// function_call.c
#include <stdio.h>

int bar(int c, int d)
{
  int e = c + d;
  return e;
}

int foo(int a, int b)
{
  return bar(a, b);
}

int main(void)
{
  foo(2, 3);
  return 0;
}
{% endhighlight %}

Compile it.

{% highlight sh %}
gcc -c function_call.c
gcc function_call.o -o function_call
{% endhighlight %}

The last step is actually:

{% highlight sh %}
ld /usr/lib64/crt1.o /usr/lib64/crti.o function_call.o -o function_call -lc -dynamic-linker /lib/ld-linux.so.2
{% endhighlight %}

`-lc` means link to `libc` library. It is default option of `gcc`, but not of `ld`.

`-dynamic-linker` is to assign dynamic linked library. 

What is inside `crt1.o` and `crti.o`? 

    $ whatis nm
    nm                   (1)  - list symbols from object files

    $ nm /usr/lib64/crt1.o
    0000000000000000 R _IO_stdin_used
    0000000000000000 D __data_start
                     U __libc_csu_fini
                     U __libc_csu_init
                     U __libc_start_main
    0000000000000000 T _start
    0000000000000000 W data_start
                     U main

`U main` means `main` is used in `crt1.o`, but not defined(`U` stands for undefined), therefore other target file need to provide the `main` for `crt1.o`.

#### Symbol Resolution

If there is an instruction `push $main's_address`, since linker doesn't know the address, `crt1.o` will replace it with `push $0x0`. When linking with `main.o`, the address will be replaced with the correct one. 

Linker is an editor, like vi and emacs. Linker edit target file.

`T _start` means `_start` is of type text, since `_start` is a piece of source code.

The `ld` command above is a simple version. Use `gcc -v` to see the details. `gcc -v function_call.c function_call`

`libc` is not linked into executable file. It is dynamiclly linked at runtime. __Dynamic linking__ requires shared library, assigned with `-l` option. After dynamic linking, the whole linking process is finished.

Startup routine calls `main()`(actually should be `int main(int argc, char *argv[])`) by a equivalent C code of `exit(main(argc, argv))`. 

`exit()` is also defined in `libc`. `exit()` will do some cleanup routine before exit the program.

`exit()` is defined in `stdlib.h` header file.

## 2. Storage layout of variables

{% highlight cpp %}
// variable.c
#include <stdio.h>

const int A = 10;
int a = 20;
static int b = 30;
int c;

int main(void)
{
	static int a = 40;
	char b[] = "Hello world";
	register int c = 50;
	
	printf("Hello world %d\n", c);
	
	return 0;
}
{% endhighlight %}

Compile it using debug mode. `gcc variable.c -g`. Then use `readelf` to see the section information.

    $ readelf -a a.out

    Section Headers:
      [Nr] Name              Type             Address           Offset
           Size              EntSize          Flags  Link  Info  Align
    ...
      [15] .rodata           PROGBITS         00000000004005f8  000005f8
           0000000000000024  0000000000000000   A       0     0     8
    ...
      [24] .data             PROGBITS         00000000006008a8  000008a8
           0000000000000010  0000000000000000  WA       0     0     4


    ...
        49: 00000000006008b0     4 OBJECT  LOCAL  DEFAULT   24 b
        50: 00000000006008b4     4 OBJECT  LOCAL  DEFAULT   24 a.2055
        65: 0000000000400608     4 OBJECT  GLOBAL DEFAULT   15 A
        66: 00000000006008ac     4 OBJECT  GLOBAL DEFAULT   24 a
        75: 00000000006008c8     4 OBJECT  GLOBAL DEFAULT   25 c    

Let's see the variables in hex format of `a.out`.

    ...

    00000600  00 00 00 00 00 00 00 00  0a 00 00 00 48 65 6c 6c  |............Hell|
    00000610  6f 20 77 6f 72 6c 64 20  25 64 0a 00 01 1b 03 3b  |o world %d.....;|
    00000620  20 00 00 00 03 00 00 00  a8 fe ff ff 3c 00 00 00  | ...........<...|
    ...
    000008a0  ce 03 40 00 00 00 00 00  00 00 00 00 14 00 00 00  |..@.............|
    000008b0  1e 00 00 00 28 00 00 00  47 43 43 3a 20 28 47 4e  |....(...GCC: (GN|

    ...

Starting from 0x60c, it is the string value "Hello world", at the end of `.rodata` section. `char []` is literal string, is read-only, equivalent to a global const array.

And also, 0x608, we find `0a`, which is `A = 10`.

`.data` starts from 0x6008a8, length 0x10, which means 0x6008a8~0x6008b8. So `a`, `b`, `a.2055` are inside this part. `a` is `GLOBAL`, `b` is made `LOCAL` by the modifier `static`, so `b` will not be processed by the linker. `a.1589` is the local variable defined in `main()`. It is staticlly allocated, not allocated when being called and being release when function returns. 

`c` is within `.bss`. __The difference between `.bss` and `.data` is__, `.bss` does not take space in the file, filled with 0 when loading.

We don't see the allocation of two local variables in `main()`. Local variable and parameter of a function is allocated on the stack. We use `objdump` to see them.

    $ objdump -dS a.out

    ...
    int main(void)
    {
      4004c4:	55                   	push   %rbp
      4004c5:	48 89 e5             	mov    %rsp,%rbp
      4004c8:	53                   	push   %rbx
      4004c9:	48 83 ec 18          	sub    $0x18,%rsp
      static int a = 40;
      char b[] = "Hello world";
      4004cd:	c7 45 e0 48 65 6c 6c 	movl   $0x6c6c6548,-0x20(%rbp)
      4004d4:	c7 45 e4 6f 20 77 6f 	movl   $0x6f77206f,-0x1c(%rbp)
      4004db:	c7 45 e8 72 6c 64 00 	movl   $0x646c72,-0x18(%rbp)
      register int c = 50;
      4004e2:	bb 32 00 00 00       	mov    $0x32,%ebx
      
      printf("Hello world %d\n", c);
      4004e7:	b8 0c 06 40 00       	mov    $0x40060c,%eax
      4004ec:	89 de                	mov    %ebx,%esi
      4004ee:	48 89 c7             	mov    %rax,%rdi
      4004f1:	b8 00 00 00 00       	mov    $0x0,%eax
      4004f6:	e8 bd fe ff ff       	callq  4003b8 <printf@plt>
      
      return 0;
      4004fb:	b8 00 00 00 00       	mov    $0x0,%eax
    }

    ...

See, for `b[]`, it moves the 12 bytes data from `.rodata` to the stack directly. The address of `b[]` is from `%rbp-0x20` to `%rbp-0x18`.

`c` is not on the stack. It is inside the register `%ebx`. That is how keyword `register` takes effect.

### Scope

Use only __local__ and __global__ to classify variable according to scope __IS NOT APPROPRIATE__. Scope can be applied to any label. There are 4 scopes in C language:

* __Function Scope__: label lives in the function
* __File Scope__: label lives from declaration to the end of the file. 
* __Block Scope__: label lives in brackets {}
* __Function Prototype Scope__: label lives in the prototype(signature) of a function. eg. `int foo(int a, int b);`

Label has 3 __Linkage__:

* __External linkage__: If the final executable file is linked by multiple files, the label refers to the same thing no matter how many times it is declared. They are `GLOBAL` label.
* __Internal linkage__: the label refers to the same thing no matter how many times it is declared within the same file.
* __No linkage__: Other than external linkage and internal linkage.

There are several difference __Storage Class Specifier__:

* __static__: staticlly allocated. Internal Linkage
* __auto__: automatically allocated on the stack, released when function returns.
* __register__: allocated on a register. If there is no register available, then it is regarded as `auto`
* __extern__: discuss in detail later
* __typedef__: define a type name

Notice that `const` is not storage class specifier. It is __Type qualifier__.

There are several kinds of variables's __Storage Duration(lifetime)__:

| | Allocated | Released |
| --- | --- | --- |
| __Static Storage Duration__ | when program starts | when program ends |
| __Automatic Storage Duration__ | when enter a block, allocated on stack | when exit the block |
| __Allocated Storage Duration__ | using `malloc` | using `free` |

## 3. C inlines assembly

To inline assembly, use `__asm__("assembly code")`

{% highlight cpp %}
#include <stdio.h>

int main() 
{
	int a = 10, b;
	__asm__(	"movl %1, %%eax\n\t"
				"movl %%eax, %0\n\t"
				:"=r"(b)
				:"r"(a)
				:"%eax"
				);
	printf("Result: %d, %d\n", a, b);
	return 0;
}
{% endhighlight %}
