---
layout: post
title: C Essense (1) - x86 Assembly Programming Basic
excerpt:
cover_image: cppcafe.jpg
tags: [c]
---

> The source code was tested and passed in [CentOS 6.4 vagrant box](http://developer.nrel.gov/downloads/vagrant-boxes/CentOS-6.4-x86_64-v20130309.box)
> Github repository: [http://github.com/allenlsy/c_essence](http://github.com/allenlsy/c_essence)
	
* [1. Simple assembly program](#1.-simple-assembly-program)
* [2. Second assembly program](#2.-second-assembly-program)
* [3. ELF file](#3.-elf-file)
	* [3.1 Target file](#3.1-target-file)
	* [3.2 Executable file](#3.2-executable-file)

* * *

## 1. Simple assembly program

Suppose we have an assembly program `hello.s`, and we need to compile and link it.

{% highlight asm %}
# hello.s
.section .data
.section .text
.globl _start
_start:
movl $1, %eax
movl $4, %ebx
int $0x80
{% endhighlight %}

In this program:

`.section` make thie code into several sections. When the program being load, each section will 
be loaded to different address, with different I/O right. 

`.data` section saves the data, it has r/w right. 

`.text` section saves the code. It has r/x right.

`.globl` declares a variable to be marked as `GLOBAL`. 

`_start` is a symbol that will be used by the linker. It is a special symbol indicates the start of the program, like `main()` in C program. If there is no `_start` symbol, then the program cannot be run directly.

Variables start with `%` means registers in the CPU. 

`movl` means move a long variable. `$1` is a number 1, be moved into `%eax`.

`int $0x80` is special. `int` command is a soft interruption command, generates an exception for the system, makes the CPU switch from user mode to privilige mode and then jump into kernel code. `$0x80` is a parameter. `int $0x80` raises a system call exception.

When there is a system call exception, the system reads the system call code from `%eax` and  the parameter for this call from `%exb`. `1` in system call means `_exit` call, `%ebx` is the actually the exit state `4`.

#### Compile, link, run

    as hello.s -o hello.o
    ld hello.o -o hello
    ./hello
    echo $?

`as` will compile hello.s to machine language, and `ld` will link __target file__ `hello.o` to an __executable file__ `hello`.

__Linking__ is a process to combine multiple target file into an executable file. During the process, it also modifies some information of the target file.

In shell, `$?` command is used to get the return value of last command. Let's run `hello`. Then we see the exit code `4`.

## 2. Second assembly program 

{% highlight asm %}
# max.s

.section .data
data_items:
    .long 3, 67, 34, 22, 45, 75, 54, 34, 44, 33, 22, 11, 66, 0

.section .text
.globl _start
_start:
    # move 0 into the index register
    movl $0, %edi

    # load the first byte of data into %eax
    mov data_items(,%edi,4), %eax

    # %eax is the biggest now, %ebx is used to store the biggest
    mov %eax, %ebx

start_loop:
    # check to see if we've hit the end. Last item is 0
    cmpl $0, %eax

    # jump to loop_exit if comparison result is equal
    je loop_exit
    
    # increase the value of %edi
    incl %edi

    # load next data_item into %eax
    movl data_items(,%edi,4), %eax

    # compare value
    cmpl %ebx, %eax

    # jumo to start_loop if comparison result is less than (<)
    jle start_loop

    # then means %eax is larger than %ebx, which is the current biggest.
    movl %eax, %ebx

    jmp start_loop

loop_exit:
    # %ebx is the status code for _exit system call and
    # it already has the maximum number
    movl $1, %eax
    int $0x80

{% endhighlight %}

Compile and run

{% highlight sh %}
as max.s -o max.o
ld max.o -o max
./max
echo $?
{% endhighlight %}

Analyse the program yourself.

## 3. ELF file 

__ELF__ is an open standard for all the executable file in UNIX. It has three types:

* Relocatable
* Executable
* Shared Object

### 3.1 Target file

![](/images/blog/cessense/pic1.png)

ELF file has two perspective to view it. From __compiler and linker's perspective__, ELF uses __Section Header Table__ to describe a set of sections. From __Loader's perspective__, ELF uses __Program Header Table__ to describe a set of segments. 

__ELF Header__ describes the system architecture and other system information, and points to Section Header Table and Program Header Table.

__Section Header Table__ stores the section description.

Compiler and linker do not need Program Header Table, so it is optional to them.

__Program Header Table__ stores the segments description. 

Loader does not need section information, so Section Header table is optional to loader.

Let's see the elf file structure, use `readelf -a max.o` command to see it. `-a` means all.

    ELF Header:
      Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
      Class:                             ELF64
      Data:                              2's complement, little endian
      Version:                           1 (current)
      OS/ABI:                            UNIX - System V
      ABI Version:                       0
      Type:                              REL (Relocatable file)
      Machine:                           Advanced Micro Devices X86-64
      Version:                           0x1
      Entry point address:               0x0
      Start of program headers:          0 (bytes into file)
      Start of section headers:          224 (bytes into file)
      Flags:                             0x0
      Size of this header:               64 (bytes)
      Size of program headers:           0 (bytes)
      Number of program headers:         0
      Size of section headers:           64 (bytes)
      Number of section headers:         8
      Section header string table index: 5

    Section Headers:
      [Nr] Name              Type             Address           Offset
           Size              EntSize          Flags  Link  Info  Align
      [ 0]                   NULL             0000000000000000  00000000
           0000000000000000  0000000000000000           0     0     0
      [ 1] .text             PROGBITS         0000000000000000  00000040
           000000000000002d  0000000000000000  AX       0     0     4
      [ 2] .rela.text        RELA             0000000000000000  000003c8
           0000000000000030  0000000000000018           6     1     8
      [ 3] .data             PROGBITS         0000000000000000  00000070
           0000000000000038  0000000000000000  WA       0     0     4
      [ 4] .bss              NOBITS           0000000000000000  000000a8
           0000000000000000  0000000000000000  WA       0     0     4
      [ 5] .shstrtab         STRTAB           0000000000000000  000000a8
           0000000000000031  0000000000000000           0     0     1
      [ 6] .symtab           SYMTAB           0000000000000000  000002e0
           00000000000000c0  0000000000000018           7     7     8
      [ 7] .strtab           STRTAB           0000000000000000  000003a0
           0000000000000028  0000000000000000           0     0     1
    Key to Flags:
      W (write), A (alloc), X (execute), M (merge), S (strings)
      I (info), L (link order), G (group), x (unknown)
      O (extra OS processing required) o (OS specific), p (processor specific)

    There are no section groups in this file.

    There are no program headers in this file.

    Relocation section '.rela.text' at offset 0x3c8 contains 2 entries:
      Offset          Info           Type           Sym. Value    Sym. Name + Addend
    000000000009  00020000000b R_X86_64_32S      0000000000000000 .data + 0
    00000000001a  00020000000b R_X86_64_32S      0000000000000000 .data + 0

    There are no unwind sections in this file.

    Symbol table '.symtab' contains 8 entries:
       Num:    Value          Size Type    Bind   Vis      Ndx Name
         0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
         1: 0000000000000000     0 SECTION LOCAL  DEFAULT    1 
         2: 0000000000000000     0 SECTION LOCAL  DEFAULT    3 
         3: 0000000000000000     0 SECTION LOCAL  DEFAULT    4 
         4: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    3 data_items
         5: 000000000000000f     0 NOTYPE  LOCAL  DEFAULT    1 start_loop
         6: 0000000000000026     0 NOTYPE  LOCAL  DEFAULT    1 loop_exit
         7: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT    1 _start

    No version information found in this file.

From here we can see the ELF Header, the Section Header, and there are not section groups and program headers.

In `Section headers`, we have `.text` and `.data` section.

Based on the output, we can depict the layout of this target file.

Starting address | Section or Header 
--|--
0 | Start of ELF Header 
0x40 | .text
0x70 | .data
0xa8 | .bss(empty)
0xa8 | .shstrtab
0xe4 | Start of Section Header Table
0x2e0 | .symtab
0x3a0 | .strtab
0x3c8 | .rela.text

We can also see the whole file by using `hexdump -C max.o`. `-C` means Canonical hex+ASCII display.

	00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
	00000010  01 00 3e 00 01 00 00 00  00 00 00 00 00 00 00 00  |..>.............|
	00000020  00 00 00 00 00 00 00 00  e0 00 00 00 00 00 00 00  |................|
	00000030  00 00 00 00 40 00 00 00  00 00 40 00 08 00 05 00  |....@.....@.....|
	00000040  bf 00 00 00 00 67 8b 04  bd 00 00 00 00 89 c3 83  |.....g..........|
	00000050  f8 00 74 12 ff c7 67 8b  04 bd 00 00 00 00 39 d8  |..t...g.......9.|
	00000060  7e ed 89 c3 eb e9 b8 01  00 00 00 cd 80 00 00 00  |~...............|
	00000070  03 00 00 00 43 00 00 00  22 00 00 00 16 00 00 00  |....C...".......|
	00000080  2d 00 00 00 4b 00 00 00  36 00 00 00 22 00 00 00  |-...K...6..."...|
	00000090  2c 00 00 00 21 00 00 00  16 00 00 00 0b 00 00 00  |,...!...........|
	000000a0  42 00 00 00 00 00 00 00  00 2e 73 79 6d 74 61 62  |B.........symtab|
	000000b0  00 2e 73 74 72 74 61 62  00 2e 73 68 73 74 72 74  |..strtab..shstrt|
	000000c0  61 62 00 2e 72 65 6c 61  2e 74 65 78 74 00 2e 64  |ab..rela.text..d|
	000000d0  61 74 61 00 2e 62 73 73  00 00 00 00 00 00 00 00  |ata..bss........|
	000000e0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	*
	00000120  20 00 00 00 01 00 00 00  06 00 00 00 00 00 00 00  | ...............|
	00000130  00 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
	00000140  2d 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |-...............|
	00000150  04 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	00000160  1b 00 00 00 04 00 00 00  00 00 00 00 00 00 00 00  |................|
	00000170  00 00 00 00 00 00 00 00  c8 03 00 00 00 00 00 00  |................|
	00000180  30 00 00 00 00 00 00 00  06 00 00 00 01 00 00 00  |0...............|
	00000190  08 00 00 00 00 00 00 00  18 00 00 00 00 00 00 00  |................|
	000001a0  26 00 00 00 01 00 00 00  03 00 00 00 00 00 00 00  |&...............|
	000001b0  00 00 00 00 00 00 00 00  70 00 00 00 00 00 00 00  |........p.......|
	000001c0  38 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |8...............|
	000001d0  04 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	000001e0  2c 00 00 00 08 00 00 00  03 00 00 00 00 00 00 00  |,...............|
	000001f0  00 00 00 00 00 00 00 00  a8 00 00 00 00 00 00 00  |................|
	00000200  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	00000210  04 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	00000220  11 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00  |................|
	00000230  00 00 00 00 00 00 00 00  a8 00 00 00 00 00 00 00  |................|
	00000240  31 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |1...............|
	00000250  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	00000260  01 00 00 00 02 00 00 00  00 00 00 00 00 00 00 00  |................|
	00000270  00 00 00 00 00 00 00 00  e0 02 00 00 00 00 00 00  |................|
	00000280  c0 00 00 00 00 00 00 00  07 00 00 00 07 00 00 00  |................|
	00000290  08 00 00 00 00 00 00 00  18 00 00 00 00 00 00 00  |................|
	000002a0  09 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00  |................|
	000002b0  00 00 00 00 00 00 00 00  a0 03 00 00 00 00 00 00  |................|
	000002c0  28 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |(...............|
	000002d0  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	000002e0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	000002f0  00 00 00 00 00 00 00 00  00 00 00 00 03 00 01 00  |................|
	00000300  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	00000310  00 00 00 00 03 00 03 00  00 00 00 00 00 00 00 00  |................|
	00000320  00 00 00 00 00 00 00 00  00 00 00 00 03 00 04 00  |................|
	00000330  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	00000340  01 00 00 00 00 00 03 00  00 00 00 00 00 00 00 00  |................|
	00000350  00 00 00 00 00 00 00 00  0c 00 00 00 00 00 01 00  |................|
	00000360  0f 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	00000370  17 00 00 00 00 00 01 00  26 00 00 00 00 00 00 00  |........&.......|
	00000380  00 00 00 00 00 00 00 00  21 00 00 00 10 00 01 00  |........!.......|
	00000390  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	000003a0  00 64 61 74 61 5f 69 74  65 6d 73 00 73 74 61 72  |.data_items.star|
	000003b0  74 5f 6c 6f 6f 70 00 6c  6f 6f 70 5f 65 78 69 74  |t_loop.loop_exit|
	000003c0  00 5f 73 74 61 72 74 00  09 00 00 00 00 00 00 00  |._start.........|
	000003d0  0b 00 00 00 02 00 00 00  00 00 00 00 00 00 00 00  |................|
	000003e0  1a 00 00 00 00 00 00 00  0b 00 00 00 02 00 00 00  |................|
	000003f0  00 00 00 00 00 00 00 00                           |........|
	000003f8

#### One by one analysis of sections

1. `.shstrtab` stores the name of each section.
2. `.strtab` section stores the name of symbols in the program.
3. `.data` section will be loaded to the memory.
4. `.bss` section(Block Started by Symbol) stores uninitialised global variable and static variables. It will be automatically initialised to 0.
5. `.rel.text` tells the linker the relocation information.
6. `.symtab` is symbol table. We can see it in `readelf` output. `Value` is the address of the symbol, not real value. `GLOBAL`, `LOCAL` is the binding.
7. `.text` need to use `objdump -d max.o` to disassemble the program. `-d` means disassemble. It shows the program after replacing the symbol with the real address.
 
---

	max.o:     file format elf64-x86-64
	
	Disassembly of section .text:
	
	0000000000000000 <_start>:
	   0:	bf 00 00 00 00       	mov    $0x0,%edi
	   5:	67 8b 04 bd 00 00 00 	mov    0x0(,%edi,4),%eax
	   c:	00 
	   d:	89 c3                	mov    %eax,%ebx
	
	000000000000000f <start_loop>:
	   f:	83 f8 00             	cmp    $0x0,%eax
	  12:	74 12                	je     26 <loop_exit>
	  14:	ff c7                	inc    %edi
	  16:	67 8b 04 bd 00 00 00 	mov    0x0(,%edi,4),%eax
	  1d:	00 
	  1e:	39 d8                	cmp    %ebx,%eax
	  20:	7e ed                	jle    f <start_loop>
	  22:	89 c3                	mov    %eax,%ebx
	  24:	eb e9                	jmp    f <start_loop>
	
	0000000000000026 <loop_exit>:
	  26:	b8 01 00 00 00       	mov    $0x1,%eax
	  2b:	cd 80                	int    $0x80

### 3.2 Executable file

Previously `max.o` is the target file. `max` is the executable file.

	$ readelf -a max
	
	ELF Header:
	  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
	  Class:                             ELF64
	  Data:                              2's complement, little endian
	  Version:                           1 (current)
	  OS/ABI:                            UNIX - System V
	  ABI Version:                       0
	  Type:                              EXEC (Executable file)
	  Machine:                           Advanced Micro Devices X86-64
	  Version:                           0x1
	  Entry point address:               0x4000b0
	  Start of program headers:          64 (bytes into file)
	  Start of section headers:          320 (bytes into file)
	  Flags:                             0x0
	  Size of this header:               64 (bytes)
	  Size of program headers:           56 (bytes)
	  Number of program headers:         2
	  Size of section headers:           64 (bytes)
	  Number of section headers:         6
	  Section header string table index: 3
	
	Section Headers:
	  [Nr] Name              Type             Address           Offset
	       Size              EntSize          Flags  Link  Info  Align
	  [ 0]                   NULL             0000000000000000  00000000
	       0000000000000000  0000000000000000           0     0     0
	  [ 1] .text             PROGBITS         00000000004000b0  000000b0
	       000000000000002d  0000000000000000  AX       0     0     4
	  [ 2] .data             PROGBITS         00000000006000e0  000000e0
	       0000000000000038  0000000000000000  WA       0     0     4
	  [ 3] .shstrtab         STRTAB           0000000000000000  00000118
	       0000000000000027  0000000000000000           0     0     1
	  [ 4] .symtab           SYMTAB           0000000000000000  000002c0
	       00000000000000f0  0000000000000018           5     6     8
	  [ 5] .strtab           STRTAB           0000000000000000  000003b0
	       0000000000000040  0000000000000000           0     0     1
	Key to Flags:
	  W (write), A (alloc), X (execute), M (merge), S (strings)
	  I (info), L (link order), G (group), x (unknown)
	  O (extra OS processing required) o (OS specific), p (processor specific)
	
	There are no section groups in this file.
	
	Program Headers:
	  Type           Offset             VirtAddr           PhysAddr
	                 FileSiz            MemSiz              Flags  Align
	  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
	                 0x00000000000000dd 0x00000000000000dd  R E    200000
	  LOAD           0x00000000000000e0 0x00000000006000e0 0x00000000006000e0
	                 0x0000000000000038 0x0000000000000038  RW     200000
	
	 Section to Segment mapping:
	  Segment Sections...
	   00     .text 
	   01     .data 
	
	There is no dynamic section in this file.
	
	There are no relocations in this file.
	
	There are no unwind sections in this file.
	
	Symbol table '.symtab' contains 10 entries:
	   Num:    Value          Size Type    Bind   Vis      Ndx Name
	     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
	     1: 00000000004000b0     0 SECTION LOCAL  DEFAULT    1 
	     2: 00000000006000e0     0 SECTION LOCAL  DEFAULT    2 
	     3: 00000000006000e0     0 NOTYPE  LOCAL  DEFAULT    2 data_items
	     4: 00000000004000bf     0 NOTYPE  LOCAL  DEFAULT    1 start_loop
	     5: 00000000004000d6     0 NOTYPE  LOCAL  DEFAULT    1 loop_exit
	     6: 00000000004000b0     0 NOTYPE  GLOBAL DEFAULT    1 _start
	     7: 0000000000600118     0 NOTYPE  GLOBAL DEFAULT  ABS __bss_start
	     8: 0000000000600118     0 NOTYPE  GLOBAL DEFAULT  ABS _edata
	     9: 0000000000600118     0 NOTYPE  GLOBAL DEFAULT  ABS _end
	
	No version information found in this file.

In ELF Header, `Type` is `EXEC`, `entry point address` is changed( it is the `_start` address).

Let's see the disassembled code.

	$ objdump -d max
	
	max:     file format elf64-x86-64
	
	
	Disassembly of section .text:
	
	00000000004000b0 <_start>:
	  4000b0:	bf 00 00 00 00       	mov    $0x0,%edi
	  4000b5:	67 8b 04 bd e0 00 60 	mov    0x6000e0(,%edi,4),%eax
	  4000bc:	00 
	  4000bd:	89 c3                	mov    %eax,%ebx
	
	00000000004000bf <start_loop>:
	  4000bf:	83 f8 00             	cmp    $0x0,%eax
	  4000c2:	74 12                	je     4000d6 <loop_exit>
	  4000c4:	ff c7                	inc    %edi
	  4000c6:	67 8b 04 bd e0 00 60 	mov    0x6000e0(,%edi,4),%eax
	  4000cd:	00 
	  4000ce:	39 d8                	cmp    %ebx,%eax
	  4000d0:	7e ed                	jle    4000bf <start_loop>
	  4000d2:	89 c3                	mov    %eax,%ebx
	  4000d4:	eb e9                	jmp    4000bf <start_loop>
	
	00000000004000d6 <loop_exit>:
	  4000d6:	b8 01 00 00 00       	mov    $0x1,%eax
	  4000db:	cd 80                	int    $0x80

The relative addresses in target file have been replaced with absolute address.

In target file, it has: 

    5:	67 8b 04 bd 00 00 00 	mov    0x0(,%edi,4),%eax

Now become:

    4000b5:	67 8b 04 bd e0 00 60 	mov    0x6000e0(,%edi,4),%eax

How does the linker know to change `0x0` to `0x6000e0`? It is based on the `.rela.text` section.

    Relocation section '.rela.text' at offset 0x3c8 contains 2 entries:
      Offset          Info           Type           Sym. Value    Sym. Name + Addend
    000000000009  00020000000b R_X86_64_32S      0000000000000000 .data + 0
    00000000001a  00020000000b R_X86_64_32S      0000000000000000 .data + 0
