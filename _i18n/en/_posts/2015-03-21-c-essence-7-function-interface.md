---
layout: post
title: "C Essense (7) - Function interface"
excerpt:
cover_image: blog/c-programmers.jpg
thumbnail: /images/blog/c-programmers-thumb.jpg
tags: [c]
---

## 1. `malloc` and `free`[](#1)

`malloc` is used to dynamiclly allocate memory by calling system call `brk`. After allocation, we should use `free` to release the memory, return the memory to `malloc`.

```c
#include <stdlib.h>
void *malloc(size_t size);
void free  (void *ptr)
```

#### Example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
    int number;
    char *msg;
} unit_t;

int main(void)
{
	unit_t *p = malloc(sizeof(unit_t));
	if (p == NULL) {
		printf("out of memory\n");
		exit(1);
	}
	p->number = 3;
	p->msg = malloc(20);
	strcpy(p->msg, "Hello world!"); printf("number: %d\nmsg: %s\n", p->number, p->msg);
	free(p->msg);
	free(p);
	p = NULL;
	return 0;
}
```

Several things to notice:

* `unit_t *p = malloc(sizeof(unit_t));`, `void *` can be implicit converted to any other pointer type.
* Although normally memory will not be exhausted, but after `malloc`, we should check whether it is successful, by checking whether the return value is `NULL`
* After `free( p )`, the memory space of `p` is returned, but the value of `p` is not changed. Now `p` is a __wild pointer__(pointing to somewhere not exist). We should set `p = NULL` after `free( p )`
* When calling `free( p )`, the program knows how large space has been allocated to `p` by `malloc`. It will free the part allocated to `p`.

## 2. pass-in parameter & pass-out parameter

```c
void func(unit_t *p);
```

If `*p` points to somewhere exist, and `func()` will read data from the space, then `*p` is called __pass-in__ parameter.

If `*p` points to nowhere, and `func()` will assign `*p` the address, then `*p` is called __pass-out__ parameter.

If `*p` points to somewhere exist, and `func()` will read data and change data in that space, then `*p` is called __value-result__ parameter.

## 3. double pointer

#### Example

```c
/* redirect_ptr.h */
#ifndef REDIRECT_PTR_H
#define REDIRECT_PTR_H
extern void get_a_day(const char **); #endif

/* redirect_ptr.c */
#include "redirect_ptr.h"
static const char *msg[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};

void get_a_day(const char **pp) {
	static int i = 0; *pp = msg[i%7]; i++;
}
/* main1.c */
#include <stdio.h>
#include "redirect_ptr.h"
int main(void)
{
	const char *firstday = NULL;
	const char *secondday = NULL; get_a_day(&firstday); get_a_day(&secondday); printf("%s\t%s\n", firstday, secondday); return 0;
}

```

Compile and Run

```sh
gcc main1.c redirect_ptr.c -o main
./main
```

## 4. Callback function

```c
void func(void (*f)(void *), void *p);
```

The first parameter of `func` is a function pointer `f`. `f` should take one parameter of type `void *`, and return a `void *` value. The second parameter is just a `void *` value.

#### Example: comparison function

```c
/* generics.h */
#ifndef GENERICS_H
#define GENERICS_H
typedef int (*cmp_t)(void *, void *);
extern void *max(void *data[], int num, cmp_t cmp);
#endif

/* generics.c */
#include "generics.h"
void *max(void *data[], int num, cmp_t cmp) {
	int i;
	void *temp = data[0]; for(i=1; i<num; i++) {
	   if(cmp(temp, data[i])<0)
	       temp = data[i];
	}
   return temp;
}

/* main2.c */
#include <stdio.h>
#include "generics.h"
typedef struct {
    const char *name;
    int score;
} student_t;

// Comparison function of two student
int cmp_student(void *a, void *b) {
    if(((student_t *)a)->score > ((student_t *)b)->score)
        return 1;
    else if(((student_t *)a)->score == ((student_t*)b)->score)
        return 0;
    else
        return -1;
}

int main(void)
{
    student_t list[4] = { {"Tom", 68}, {"Jerry", 72}, {"Moby", 60}, {"Kirby", 89} };
    student_t *plist[4] = {&list[0], &list[1], &list[2], &list[3]};
    student_t *pmax = max((void **)plist, 4, cmp_student);
    printf("%s gets the highest score %d\n", pmax->name, pmax->score);
    return 0;
}
```

## 5. Variable length arguments

```c
int printf(const char *format, …)
```

#### Example: an implementation of `printf`

```c
#include <stdio.h>
#include <stdarg.h>
void myprintf(const char *format, ...)
{
    va_list ap;
    char c;
    va_start(ap, format);
    while (c = *format++) {
        switch(c) {
            case 'c': {
                /* char is promoted to int when passed through '...' */
                char ch = va_arg(ap, int); putchar(ch);
                break;
            }
            case 's': {
                char *p = va_arg(ap, char *); fputs(p, stdout);
                break;
            }
            default:
                putchar(c);
        }
    }
    va_end(ap);
}
int main(void)
{
    myprintf("c\ts\n", '1', "hello");
    return 0;
}
```

Variable length arguments requires `stdarg.h`, and `va_list` type and `va_start`, `va_atg`, `va_end` macro.

* `va_list ap`: `ap` is a pointer
* `va_start(ap, format)`: let `ap` points to the next memory position of `format`
* `va_arg(ap, int)`: get next value in `ap` as `int`, and move ap to the next position
* `va_end(ap)`: is a callback. Will be called at here.

```c
#define va_start(v,l)	__builtin_va_start(v,l)
#define va_end(v)	__builtin_va_end(v)
#define va_arg(v,l)	__builtin_va_arg(v,l)
```



