---
layout: post
title: C Essense (3) - Linkage
excerpt:
cover_image: cppcafe.jpg
tags: [c]

---

> The source code was tested and passed in [CentOS 6.4 vagrant box](http://developer.nrel.gov/downloads/vagrant-boxes/CentOS-6.4-x86_64-v20130309.box)
> Github repository: [http://github.com/allenlsy/c_essence](http://github.com/allenlsy/c_essence)

* [1. Link multiple target file](#1.-link-multiple-target-file)
* [2. Definition and Declaration](#2.-definition-and-declaration)
	* [2.1 `extern` and `static` keyword](#2.1-extern-and-static-keyword)
	* [2.2 Header file](#2.2-header-file)
* [3. Static library](#3.-static-library)
* [4. Shared library](#4.-shared-library)
	* [4.1 Without `-fPIC` option](#4.1-without--fpic-option)
	* [4.2 With `-fPIC` option](#4.2-with--fpic-option)
	* [4.3 Dynamic linking](#4.3-dynamic-linking)
	* [4.4 Shared library naming convention](#4.4-shared-library-naming-convention)

* * *

## 1. Link multiple target file 

We use a stack program as an example.

{% highlight cpp %}
// stack.c
char stack[512];
int top = -1;

void push(char c)
{
	stack[++top] = c;
}

char pop(void) 
{
	return stack[--top];
}

int is_empty(void)
{
	return top == -1;
}
{% endhighlight %}

{% highlight cpp %}
// main.c
#include <stdio.h>

int a, b = 1;

int main(void)
{
	push('a');
	push('b');
	push('c');
	
	while(!is_empty())
		putchar(pop());
	putchar('\n');
	
	return 0;
}
{% endhighlight %}

Compile them together. `gcc main.c stack.c -o main`

Use `nm` to check the label table.

## 2. Definition and Declaration 

### 2.1 `extern` and `static` keyword 

During the compilation, the order of `main.c` and `stack.c` matters. 

If we compile `main.c` separately, with `-Wall` option, `gcc -c main.c -Wall`, we find a warning.

    $ gcc -c main.c -Wall

    main.c: In function ‘main’:
    main.c:7: warning: implicit declaration of function ‘push’
    main.c:11: warning: implicit declaration of function ‘is_empty’
    main.c:12: warning: implicit declaration of function ‘pop’

Compiler cannot find the function prototype, therefore it create implicit declaration.

{% highlight cpp %}
int push(char);
int pop(void);
int is_empty(void);
{% endhighlight %}

But we should not depend on implicit declaration, because it may make mistake.

To eliminate the warning:

{% highlight cpp %}
// main.c
#include <stdio.h>

extern void posh(char);
extern char pop(void);
extern int is_empty(void);

int main(void)
{
	push('a');
	push('b');
	push('c');
	
	while(!is_empty())
		putchar(pop());
	putchar('\n');
	
	return 0;
}
{% endhighlight %}

`extern` keyword of `push` means, `push` will be defined with external linkage. And if we don't write `extern`, it still have external linkage.

If a function is `static`, then it has static linkage. It will only be recognised within the file.

Now, if from `main.c`, I want to access `top` in `stack.c`, just add a line `extern int top;`. Since `top` already has the external linkage, it will be linked correctly.

{% highlight cpp %}
// main.c
#include <stdio.h>

extern void posh(char);
extern char pop(void);
extern int is_empty(void);

int main(void)
{
	push('a');
	push('b');
	push('c');
	
	extern int top;
	printf("%d\n", top);
	
	while(!is_empty())
		putchar(pop());
	putchar('\n');
	
	return 0;
}
{% endhighlight %}

But for a stack, it should hide `top` variable. 

{% highlight cpp %}
// stack.c
static char stack[512];
static int top = -1;

void push(char c)
{
	stack[++top] = c;
}

char pop(void) 
{
	return stack[--top];
}

int is_empty(void)
{
	return top == -1;
}
{% endhighlight %}

### 2.2 Header file 

Header file is used for recursively including module. Let's make a header file for stack.

{% highlight cpp %}
// stack.h
#ifndef STACK_H
#define STACK_H
extern void push(char);
extern char pop(void);
extern int is_empty(void);
#endif
{% endhighlight %}

Then in `main.c`, we only need to include `stack.h`, without declare three extern method prototypes.

{% highlight cpp %}
// main.c
#include <stdio.h>
#include "stack.h"
int main(void)
{
	push('a');
	push('b');
	push('c');
	
	while(!is_empty())
		putchar(pop());
	putchar('\n');
	
	return 0;
}
{% endhighlight %}

Headers included using `<>`, gcc will look for them in the order of:

* folders that `-I` option assigns
* system header files, usually in `/usr/include`

Headers included using `""`, gcc will look for them in the order of:

* current folder
* folders that `-I` option assigns
* system header files

#### Example 1

Suppose we have a folder structure like this:

  $ tree

    .
    ├── main.c
    └── stack
        ├── stack.c
        └── stack.h

    1 directory, 3 files

Use `gcc -c main.c -Istack` to compile. `-I` tells gcc to look for headers in _stack_ folder.

__Header guard__ protects including headers repeatedly. The main reason is that some kinds of code, like `typedef`, should not be defined multiple times.

> An important concept __Previous linkage__ of a label: the same type of linkage as last time.

## 3. Static library 

`libc` is a static library.

To illustrate how to create a static library file, we separate `stack.c` into four files.

{% highlight cpp %}
/* stack.c */
char stack[512];
int top = -1;

/* push.c */
extern char stack[512];
extern int top;

void push(char c) 
{
	stack[++top] = c;
}

/* pop.c */
extern char stack[512];
extern int top;

char pop(voi)
{
	return stack[top--];
}

/* is_empty.c */
extern int top;

int is_empty(void)
{
	return top == -1;
}

/* stack.h */
#ifndef STACK_H
#define STACK_H
extern void push(char);
extern char pop(void);
extern int is_empty(void);
#endif

/* main.c */
#include <stdio.h>
#include "stack.h"

int main(void)
{
	push('a');
	return 0;
}
{% endhighlight %}

The folder structure should be:

    .
    ├── main.c
    └── stack
        ├── is_empty.c
        ├── pop.c
        ├── push.c
        ├── stack.c
        └── stack.h

    1 directory, 6 files

Compile the whole project using `gcc -c stack/stack.c stack/push.c stack/pop.c stack/is_empty.c`.

Then create the static library file `libstack.a`:

{% highlight sh %}

$ ar rs libstack.a stack.o push.o pop.o is_empty.o

ar: creating libstack.a
{% endhighlight %}

`ar` means archive, similar to `tar` command. Option `r` means replace existing file into archive. Option `s` means create static library, with static index. `ranlib` is another command for creating static index.

Now we can compile `main.c` with `libstack.a`, `gcc main.c -L. -lstack -Istack -o main`

`-L` option assigns the path of library files. `.` means current folder. This option is not optional. 

`-l` option tells the compiler to link `libstack`

`-I` option tells the compiler the path of header files

The default searching path for compile: `gcc -print-search-dirs`

Compiler looks for library in the order of shared library and static library.

__Shared library__ will not be linked by linker. Linker just assign the dynamic linker for it and tells the require shared library file name. Static library will be compile and linked into the executable.

## 4. Shared library 

The files to composite a shared library are different than normal target files. It must use option `-fPIC` to compile them.

### 4.1 Without `-fPIC` option 

We can check the difference in the compiled `push.o` file.

    $ gcc -c -g stack/stack.c stack/push.c stack/pop.c stack/is_empty.c
    $ objdump -dS push.o

    push.o:     file format elf64-x86-64


    Disassembly of section .text:

    0000000000000000 <push>:
       0:   55                      push   %rbp
       1:   48 89 e5                mov    %rsp,%rbp
       4:   89 f8                   mov    %edi,%eax
       6:   88 45 fc                mov    %al,-0x4(%rbp)
       9:   48 8b 05 00 00 00 00    mov    0x0(%rip),%rax        # 10 <push+0x10>
      10:   8b 00                   mov    (%rax),%eax
      12:   8d 50 01                lea    0x1(%rax),%edx
      15:   48 8b 05 00 00 00 00    mov    0x0(%rip),%rax        # 1c <push+0x1c>
      1c:   89 10                   mov    %edx,(%rax)
      1e:   48 8b 05 00 00 00 00    mov    0x0(%rip),%rax        # 25 <push+0x25>
      25:   8b 00                   mov    (%rax),%eax
      27:   48 8b 15 00 00 00 00    mov    0x0(%rip),%rdx        # 2e <push+0x2e>
      2e:   48 98                   cltq   
      30:   0f b6 4d fc             movzbl -0x4(%rbp),%ecx
      34:   88 0c 02                mov    %cl,(%rdx,%rax,1)
      37:   c9                      leaveq 
      38:   c3                      retq   

The address of `stack` and `top` are 0x0. They will be modified during relocation.

    $ readelf -a push.o

    ...
    Relocation section '.rela.text' at offset 0x598 contains 4 entries:
      Offset          Info           Type           Sym. Value    Sym. Name + Addend
    00000000000c  000a00000009 R_X86_64_GOTPCREL 0000000000000000 top - 4
    000000000018  000a00000009 R_X86_64_GOTPCREL 0000000000000000 top - 4
    000000000021  000a00000009 R_X86_64_GOTPCREL 0000000000000000 top - 4
    00000000002a  000b00000009 R_X86_64_GOTPCREL 0000000000000000 stack - 4

    Relocation section '.rela.eh_frame' at offset 0x5f8 contains 1 entries:
      Offset          Info           Type           Sym. Value    Sym. Name + Addend
    000000000020  000200000002 R_X86_64_PC32     0000000000000000 .text + 0
    ...

It says there are 4 things need to be modified during relocation.

Let's link them to a executable file and then disassemble it.

    $ gcc -g main.c stack.o push.o pop.o is_empty.o -Istack -o main
    $ objdump -dS main

    ...

    000000000040050c <push>:
      40050c:       55                      push   %rbp
      40050d:       48 89 e5                mov    %rsp,%rbp
      400510:       89 f8                   mov    %edi,%eax
      400512:       88 45 fc                mov    %al,-0x4(%rbp)
      400515:       48 8b 05 4c 04 20 00    mov    0x20044c(%rip),%rax        # 600968 <_DYNAMIC+0x198>
      40051c:       8b 00                   mov    (%rax),%eax
      40051e:       8d 50 01                lea    0x1(%rax),%edx
      400521:       48 8b 05 40 04 20 00    mov    0x200440(%rip),%rax        # 600968 <_DYNAMIC+0x198>
      400528:       89 10                   mov    %edx,(%rax)
      40052a:       48 8b 05 37 04 20 00    mov    0x200437(%rip),%rax        # 600968 <_DYNAMIC+0x198>
      400531:       8b 00                   mov    (%rax),%eax
      400533:       48 8b 15 36 04 20 00    mov    0x200436(%rip),%rdx        # 600970 <_DYNAMIC+0x1a0>
      40053a:       48 98                   cltq   
      40053c:       0f b6 4d fc             movzbl -0x4(%rbp),%ecx
      400540:       88 0c 02                mov    %cl,(%rdx,%rax,1)
      400543:       c9                      leaveq 
      400544:       c3                      retq   
      400545:       90                      nop
      400546:       90                      nop
      400547:       90                      nop

    ...

All the 0x0 address are replaced with absolute addresses. This is __Relocation__.

### 4.2 With `-fPIC` option 

    $ gcc -c -g -fPIC stack/stack.c stack/push.c stack/pop.c stack/is_empty.c
    $ objdump -dS push.o

    push.o:     file format elf64-x86-64


    Disassembly of section .text:

    0000000000000000 <push>:
    extern char stack[512];
    extern int top;

    void push(char c) 
    {
       0:   55                      push   %rbp
       1:   48 89 e5                mov    %rsp,%rbp
       4:   89 f8                   mov    %edi,%eax
       6:   88 45 fc                mov    %al,-0x4(%rbp)
        stack[++top] = c;
       9:   48 8b 05 00 00 00 00    mov    0x0(%rip),%rax        # 10 <push+0x10>
      10:   8b 00                   mov    (%rax),%eax
      12:   8d 50 01                lea    0x1(%rax),%edx
      15:   48 8b 05 00 00 00 00    mov    0x0(%rip),%rax        # 1c <push+0x1c>
      1c:   89 10                   mov    %edx,(%rax)
      1e:   48 8b 05 00 00 00 00    mov    0x0(%rip),%rax        # 25 <push+0x25>
      25:   8b 00                   mov    (%rax),%eax
      27:   48 8b 15 00 00 00 00    mov    0x0(%rip),%rdx        # 2e <push+0x2e>
      2e:   48 98                   cltq   
      30:   0f b6 4d fc             movzbl -0x4(%rbp),%ecx
      34:   88 0c 02                mov    %cl,(%rdx,%rax,1)
    }
      37:   c9                      leaveq 
      38:   c3                      retq   


`stack` and `top` are no longer 0x0. They are `0x0(%rip)`. 

    $ readelf -a push.o

    ...
    Relocation section '.rela.text' at offset 0xb50 contains 4 entries:
      Offset          Info           Type           Sym. Value    Sym. Name + Addend
    00000000000c  001000000009 R_X86_64_GOTPCREL 0000000000000000 top - 4
    000000000018  001000000009 R_X86_64_GOTPCREL 0000000000000000 top - 4
    000000000021  001000000009 R_X86_64_GOTPCREL 0000000000000000 top - 4
    00000000002a  001100000009 R_X86_64_GOTPCREL 0000000000000000 stack - 4
    ...

Create shared library.

    $ gcc -shared -o libstack.so stack.o push.o pop.o is_empty.o
    $ objdump -dS libstack.so

    ...
    00000000000005ec <push>:
    extern char stack[512];
    extern int top;

    void push(char c) 
    {
     5ec:   55                      push   %rbp
     5ed:   48 89 e5                mov    %rsp,%rbp
     5f0:   89 f8                   mov    %edi,%eax
     5f2:   88 45 fc                mov    %al,-0x4(%rbp)
        stack[++top] = c;
     5f5:   48 8b 05 24 03 20 00    mov    0x200324(%rip),%rax        # 200920 <_DYNAMIC+0x190>
     5fc:   8b 00                   mov    (%rax),%eax
     5fe:   8d 50 01                lea    0x1(%rax),%edx
     601:   48 8b 05 18 03 20 00    mov    0x200318(%rip),%rax        # 200920 <_DYNAMIC+0x190>
     608:   89 10                   mov    %edx,(%rax)
     60a:   48 8b 05 0f 03 20 00    mov    0x20030f(%rip),%rax        # 200920 <_DYNAMIC+0x190>
     611:   8b 00                   mov    (%rax),%eax
     613:   48 8b 15 16 03 20 00    mov    0x200316(%rip),%rdx        # 200930 <_DYNAMIC+0x1a0>
     61a:   48 98                   cltq   
     61c:   0f b6 4d fc             movzbl -0x4(%rbp),%ecx
     620:   88 0c 02                mov    %cl,(%rdx,%rax,1)
    }
     623:   c9                      leaveq 
     624:   c3                      retq   
     625:   90                      nop
     626:   90                      nop
     627:   90                      nop

    ...

At 5f5, 0x200324 stores another address. That address is the address of `top`. This is called __Indirect addressing__.

Now compile and link `main.c` with `libstack.so`.

    $ gcc main.c -g -L. -lstack -Istack -o main
    $ ./main

    ./main: error while loading shared libraries: libstack.so: cannot open shared object file: No such file or directory

Why can't gcc find `libstack.so`? We can use `ldd` command to check which libraries the executable file depends on.

    $ ldd main

            linux-vdso.so.1 =>  (0x00007fffe17f1000)
            libstack.so => not found
            libc.so.6 => /lib64/libc.so.6 (0x00007fc962e17000)
            /lib64/ld-linux-x86-64.so.2 (0x00007fc9631b4000)

The searching order is decided by the dynamic linker. `man 8 ld.so` can see the searching order.

       The shared libraries needed by the program are searched for in the following order:

       o  (ELF only) Using the directories specified in the DT_RPATH dynamic section attribute of the binary if present and DT_RUNPATH  attribute  does  not  exist.
          Use of DT_RPATH is deprecated.

       o  Using the environment variable LD_LIBRARY_PATH.  Except if the executable is a set-user-ID/set-group-ID binary, in which case it is ignored.

       o  (ELF only) Using the directories specified in the DT_RUNPATH dynamic section attribute of the binary if present.

       o  From  the  cache file /etc/ld.so.cache which contains a compiled list of candidate libraries previously found in the augmented library path.  If, however,
          the binary was linked with the -z nodeflib linker option, libraries in the default library paths are skipped.

       o  In the default path /lib, and then /usr/lib.  If the binary was linked with the -z nodeflib linker option, this step is skipped.


To summarise, __the best way to solve the problem__, is the second way described in the man page. 

* add current path to `/etc/ld.so.conf`
* `sudo ldconfig -v` to reconfig and shows all the shared library. 
* `ldd main` again

Another way is to add `libstack.so` to system library. Usually `/usr/lib`.

### 4.3 Dynamic linking 

Let's look into `main` to see how it call `push()` from the shared library.

    $ objdump -dS main

    ...
    Disassembly of section .plt:

    00000000004004a0 <__libc_start_main@plt-0x10>:
      4004a0:       ff 35 a2 04 20 00       pushq  0x2004a2(%rip)        # 600948 <_GLOBAL_OFFSET_TABLE_+0x8>
      4004a6:       ff 25 a4 04 20 00       jmpq   *0x2004a4(%rip)        # 600950 <_GLOBAL_OFFSET_TABLE_+0x10>
      4004ac:       0f 1f 40 00             nopl   0x0(%rax)

    00000000004004b0 <__libc_start_main@plt>:
      4004b0:       ff 25 a2 04 20 00       jmpq   *0x2004a2(%rip)        # 600958 <_GLOBAL_OFFSET_TABLE_+0x18>
      4004b6:       68 00 00 00 00          pushq  $0x0
      4004bb:       e9 e0 ff ff ff          jmpq   4004a0 <_init+0x18>

    00000000004004c0 <push@plt>:
      4004c0:       ff 25 9a 04 20 00       jmpq   *0x20049a(%rip)        # 600960 <_GLOBAL_OFFSET_TABLE_+0x20>
      4004c6:       68 01 00 00 00          pushq  $0x1
      4004cb:       e9 d0 ff ff ff          jmpq   4004a0 <_init+0x18>

    ...

    00000000004005b4 <main>:
    #include <stdio.h>
    #include "stack.h"

    int main(void)
    {
      4005b4:       55                      push   %rbp
      4005b5:       48 89 e5                mov    %rsp,%rbp
        push('a');
      4005b8:       bf 61 00 00 00          mov    $0x61,%edi
      4005bd:       e8 fe fe ff ff          callq  4004c0 <push@plt>
        return 0;
      4005c2:       b8 00 00 00 00          mov    $0x0,%eax
    }
      4005c7:       c9                      leaveq 
      4005c8:       c3                      retq   
      4005c9:       90                      nop
      4005ca:       90                      nop
      4005cb:       90                      nop
      4005cc:       90                      nop
      4005cd:       90                      nop
      4005ce:       90                      nop
      4005cf:       90                      nop

    ...

In `main(void)`, `push` is called by `callq  4004c0 <push@plt>`. Shared library is location irrelevant code, loaded to any address during runtime.

To see where it is allocated during runtime, we use `gdb`.

    $ gdb main

    GNU gdb (GDB) Red Hat Enterprise Linux (7.2-60.el6_4.1)
    Copyright (C) 2010 Free Software Foundation, Inc.
    License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
    and "show warranty" for details.
    This GDB was configured as "x86_64-redhat-linux-gnu".
    For bug reporting instructions, please see:
    <http://www.gnu.org/software/gdb/bugs/>...
    Reading symbols from /home/vagrant/proj/blog/linkage/shared_library/main...done.
    (gdb) start
    Temporary breakpoint 1 at 0x4005b8: file main.c, line 6.
    Starting program: /home/vagrant/proj/blog/linkage/shared_library/main 

    Temporary breakpoint 1, main () at main.c:6
    6           push('a');
    Missing separate debuginfos, use: debuginfo-install glibc-2.12-1.107.el6.x86_64
    (gdb) si
    0x00000000004005bd      6           push('a');
    (gdb) si
    0x00000000004004c0 in push@plt ()
    (gdb) si
    0x00000000004004c6 in push@plt ()
    (gdb) si
    0x00000000004004cb in push@plt ()
    (gdb) si
    0x00000000004004a0 in ?? ()
    (gdb) si
    0x00000000004004a6 in ?? ()
    (gdb) si
    0x00007ffff7df1660 in _dl_runtime_resolve () from /lib64/ld-linux-x86-64.so.2
    (gdb) 

Use `si` to go into the assembly code. At last it does into the dynamic linker `/lib64/ld-linux-x86-64.so.2`. This dynamic linker will find `push()`, and after that the program can cal `push()`.

### 4.4 Shared library naming convention 

The name consists of real name, soname and linker name. __Soname__ is a symbolic link name, contains only primary version number. Library files with the same soname must have the same interface. `libcap.so.1.10` and `libcap.so.1.11` have the same interface. It provides convenience for upgrading. `libc-2.8.90.so` is special. The primary version number is 6, not `2` or `2.8`.

Some linker names are symbolic links to a library, some are linking script. 

{% highlight sh %}

$ gcc -shared -Wl,-soname,libstack.so.1 -o libstack.so.1.0 stack.o push.o pop.o is_empty.o

$ gcc --help 

...
  -Wl,<options>            Pass comma-separated <options> on to the linker
...
{% endhighlight %}

`-Wl,-soname,libstack.so.1` means `-soname libstack.so.1` is the option passed by gcc to the linker.

Now we have the `libstack.so.1.0` file. Its real name is `libstack.so.1.0`, and its soname is `libstack.so.1`

    $ readelf -a libstack.so.1.0

    ...
    Dynamic section at offset 0x7a0 contains 21 entries:
      Tag        Type                         Name/Value
     0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
     0x000000000000000e (SONAME)             Library soname: [libstack.so.1]
     0x000000000000000c (INIT)               0x4f0
     0x000000000000000d (FINI)               0x6b8
     0x000000006ffffef5 (GNU_HASH)           0x1b8
    ...
