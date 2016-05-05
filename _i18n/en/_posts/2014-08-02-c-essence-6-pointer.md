---
layout: post
title: C Essense (6) - Pointer
excerpt:
cover_image: blog/c-programmers.jpg
thumbnail: /images/blog/c-programmers-thumb.jpg
tags: [c]

---

* [1. Pointer Review](#1.-pointer-review)
* [2. Pointer and `const`](#2.-pointer-and-const)
* [3. Pointer of pointer & pointer array](#3.-pointer-of-pointer-&-pointer-array)
* [4. Pointer to an array & multi-dimention array](#4.-pointer-to-an-array-&-multi-dimention-array)
* [5. Function Type & Function Pointer](#5.-function-type-&-function-pointer)
* [6. Incomplete type & Complex declaration](#6.-incomplete-type-&-complex-declaration)

* * *

## 1. Pointer Basic

Although pointer may point to different data type, eg. `int *`, `float *`, they all take 4 bytes in memory, to store 32 bit virtual address. It takes 8 bytes on 64-bit platform.

Define multiple pointer in one line: `int *p. *q`.

`int *p` initiates `p` to a random address. It may lead to modifying existing data. We should always initialise with `int *p = NULL;`.

`NULL` is defined in `stddef.h` as `#define NULL ((void *)0)`.

`void *` can be a pointer of any type. But we cannot dereference it. We need to convert it to a pointer to a certain type first.

### Pointer and array

Pointer in function prototype can also be written as array. `void func(int a[10])` equals `void func(int *a)` equals `void func(int a[])`.

### Pointer and struct

```c
struct unit {
        char c;
        int num;
};
struct unit u;
struct unit *p = &u;
```

`(*p).c` and `p->c` are the same.

## 2. Pointer and `const`

* `const int *a`: pointer of a const int. Therefore, the value cannot be changed, but a can point to else where.
* `int const *a`: same as above
* `int * const a`: a constant pointer points to a int. `*a` can be changed, but `a` cannot point to else where.
* `int const * const a`: combination of the two above. Both the address and the value cannot be changed.

Using `const` where we can has some benefit:

1. It tells people this variable should not be modified in scope.
2. Help compiler check syntax
3. Help compiler optimize

## 3. Pointer of pointer & pointer array

Look at an example

```c
int i;
int *pi = &i;
int **ppi = &pi;
```

`ppi` is the pointer of a pointer.

`int *a[10]` defines a array of 10, the element type is `int *`. `a` is called __array of pointers__

In `int main(int argc, char *argv[])`, `argv` is a pointer to pointer, not an array of pointers. In function signature, `[]` stands for pointer, not array. `char * []` is equivalent to `char **argv`. __The reason of doing so is to tell people `argv` is a pointer to the first element of an array__. The element type of the array is `char *`.

Here is a picture shows what is `argv`:

![](/images/blog/cessense/pic61.png)

## 4. Pointer to an array & multi-dimention array

Here is the declaration of a pointer to an array of 10 integers:

```c
int (*a)[10];
```

`[]` has higher priority of `*`.

`int *a[10]` can be divided into two lines:

```c
typedef int *t;
t a[10];
```

`t` is type of `int *`. `a` is an array of `t`.

`int (*a)[10]` can be divided into two lines:

```c
typedef int t[10];
t *a;
```

`t` is a type of an array of 10 (`int (*)[10]`). `a` is an pointer of `t`.

```c
int a[10];
int (*pa)[10] = &a;
```

`a` is an array. `&a` is type of `int (*)[10]`. `&a[0]` is type of `int *`. `&a` and `&a[0]` have same address value, but of different type. `pa` is the pointer of `a`, thus `*pa` is array `a`. Thus `(*pa)[0]` is `a[0]`. Notice that `*pa` is also `pa[0]`, thus `(*pa)[0]` equals to
`pa[0][0]`. `pa` is like a name of a 2 dimension array.

```c
int a[5][10];
int (*pa)[10] = &a[0];
```

`pa` is the pointer to a 10-integer array, which is the head of `a[0]`. `pa[1][2]` is equal to `a[1][2]`. But `pa` is more flexible than `a`, because `pa` can be changed to pointer to another array.

## 5. Function Type & Function Pointer

```c
#include <stdio.h>
void say_hello(const char *str) {
  printf("Hello %s\n", str);
}
int main(void)
{
  void (*f)(const char *) = say_hello;
  f("Guys");
  return 0;
}
```

`void (*f)(const char *)` is of function pointer type. It refers to a function that returns void, and its arguments is a `const char *`. `say_hello` is a function of this type, thus `f` can point to `say_hello`.

```c
typedef int F(void);

// wrong declaration // F h(void);

F *e(void);
```

`F` is a function type. `e` is a functions, that takes no argument, and returns a function pointer of `F`. But, things like `int (*fp)(void)` is a function pointer, not like `e`, a function.

Use function pointer, it is more flexible to call functions that has the same return type and same arguments.

## 6. Incomplete type & Complex declaration

![](/images/blog/cessense/pic62.png)

There are 3 types in C language:

* Function type
* Object struct type
* Incomplete type

__Incomplete type__ is a type that has not been defined completely yet. Compiler does not know the size of the type.

```c
struct s;
union u;
char str[];
```

Incomplete type variable can be declared multiple times, to build a complete type. If it does not have a complete type until the end of program, compiler will raise error.

```c
char str[];
char str[10];
```

The usage of this is, sometimes, the first declaration is in the header file, and the second one is in `.c` file.

__Incomplete struct__ is important:

```c
struct s {
  struct t *pt;
};

struct t {
  struct s *ps;
};
```

When compiler runs to `struct t *pt`, it does not know `struct t`. But it know, `*pt` takes 4 bytes. Thus `struct s` is complete. Compiler complete `t` in following code.

This type definition is wrong:

```c
struct s {
  struct t ot;
};

struct t {
  struct s os;
}
```

In `struct`, we can define pointers recursively, but not object. `struct s` requires knowledge of `struct t`, and `struct t` requires knowledge of `struct s`. It is recursive, and cannot be compiled.

We can define it like this:

```c
struct s {
  char data[6];
  struct s* next;
}
```

### Complete type

```c
typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler);
```

This is from Linux `signal(2)`. `sighandler_t` defines a function, returns `void`, and has one argument `int`. `signal` is a function, takes two arguments, and returns a `sighandler_t`. If combine these two lines:

```c
void (*signal(int signum, void (*handler)(int)))(int);
```

When analysing complex type, there are some basic forms:

* `T *p`
* `T a[]`: a is an array of T
* `T1 f(T2, T3)`

Look at an example:

```c
int (*(*fp)(void *))[10];
```

1. `(*fp)` indicates `fp` is a pointer:

```c
typedef int (*T1(void *))[10];
T1 *fp;
```

2. `T1` is a function, takes `void *` and returns `T2`

```c
typedef int (*t2)[10];
typedef T2 T1(void *);
T1 *fp;
```

3. `T2` and `*` together, `T2` is a pointer to `T3`

```c
typedef int T3[10];
typedef T3 *T2;
typedef T2 T1(void *);
T1 *fp;

```
