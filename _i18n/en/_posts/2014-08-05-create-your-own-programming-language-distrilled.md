---
layout: post
title: C Essense (6) - Pointer
excerpt:
cover_image: blog/c-programmers.jpg
thumbnail: /images/blog/c-programmers-thumb.jpg
tags: []
draft: true
---

# Four parts of a langauge

* lexer
* parser
* interpreter
* runtime

![p7]()

We create a langauge called __Awesome__, which combines Ruby and Python

### LEXER

Tokenizer of the language, which converts the input, the code into tokens that __parser__ can understand.

Some existing tools to be

1. Lex (Flex, code my Eric)
2. Rexical (ruby gem)
3. Ragel: _State machine compiler_


##### Python style

```python
if tasty == True:
  print "Delicious!"
```



Use block `INDENT` and `DEDENT` instead of `{` and `}`.

For indentation-parsing algorithms, we need to track two things: __current indentation level__ and __stack of indentation levels__. When you encounter a line break followed by spaces, you update the indentation level.

```ruby
lexer class

```

After this, we can test the code:

```ruby
test file
```

### PARSER

Parser contextualizes tokens by organizing them in a structure. The lexer produces an array of tokens; the parser produces a tree of nodes.

The most common parser is an __Abstract Syntax Tree__, or AST.

    [<Call name=print,
            arguments=[,String value="I ate">,
                      <Number value=3>,
                      <Local name=pies>]
    >]

Here is the tree:

![p18]()

#### Bison

Bison is a modern version of YACC(Yet Another Compiler Compiler), because it compiles a grammar to a compiler of tokens. It has been ported to several target languages

* [Racc for Ruby]()
* [Ply for Python]()
* [JavaCC for Java]()

Bison compiles a grammar to parser. Here is how a YACC grammar ruule is defined:





#### Other parsers

* Lemon
* Antlr
* Pegs

####Operator precedence

Parsing `x + y * z` should not produce the same result as `(x + y) * z`. There should be a __operator precedence table__. YACC-based parsers implement the [Shunting Yard algorithm]() in which you give a precedence level to each kind of operator. Operators are declared in Bison and YACC with `%left` and `%right` macros.

Here is the operator precedence table for Awesome:


    code here on p21

The higher the precedence, the sonner the operator will be parsed. If several operators having the same precedence are competing to be parsed , declare with the `left` and `right` keyword before the token.

#### Coonectin the Lexer and Parser in Awesome

We use Racc, the Ruby version of Yacc, for Awesome.

```ruby
grammer.y on p22



```

We generate the parser with: `racc -o parser.rb grammer.y`. This will create a `Parser` class that we can use to parse our code.

### Runtime Model

Runtime model is how we represent its objects, its methods, its types, its structure in memory.

When desigining runtime, three factors you will want to consider:

* __Speed__
* __Flexibility__: the more you allow the user to modify the language, the more powerful it is
* __Memory usage__

There are several ways to model your runtime:

#### Procedural

One of the simplest, like C and PHP (before version 4). Thre aren't any objects and all methods often share the same namespace.

#### Class-based

Java, Python, Ruby

#### Prototype-based

Except for Javascript, no Prototype-based languages have reached widespread popularity yet. Everything is a clone of an object

#### Functional

Lisp, trats compitation as the evaluation of mathematical functions and avoids state and mutable data.

* * *

Awesome uses Class-based runtimes.

`AwesomeObject` class is the central object of our runtime. Everything in runtime needs to be an  instance of `AwesomeObject`.


```ruby
code on p30
```

`Class` is also of `Object`:

```ruby
code on p30
```

`Method` object, stores the method of the language:

```ruby
code on p31
```

We use `call` method in Ruby to evaluating a method

```ruby
p = proc do |arg1, arg2|
  # ...
end
p.call(1, 2)
```

Before we bootstrap our runtime, there is one missing object we need to define and that is the context of evaluation. The `Context` object encapsulates the environment of evaluation of a specific block of code. It will keep track of the following:

* Local variables
* value of `self`
* current class

Here is the `Context` class:

```ruby
Context class on p33
```

Now we can bootstrap the runtime. We need to populate the runtime with a fre object: `Class`, `Object`, `true`, `false`, `nil` and a few core methods.

```ruby
bootstrap code on p33

```

### Interpreter

The interpreter is the module that evaluates the code. __It reads the AST and execites each action associated with the nodes, and then modifies the runtime.

![pic on p36]()

The common approach to execute an AST is to implement a [Visitor class]() that visits all the nodes one by one, running the appropriate code. But for simplicity, we'll let each node handle its evaluation.

We add a new method to each node: `eval`.

```ruby
eval method on p37
```

We call `eval` on the root node, all children nodes are evaluated.

Let's run our first full program.

```ruby
code on p40
```

We make a interactive interpreter here:

```ruby
interpreter on p41
```

# Compilation
