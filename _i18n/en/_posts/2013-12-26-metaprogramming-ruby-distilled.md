---
layout: post
title: "Metaprogramming Ruby Distilled"
subtitle: NOTES on Metaprogramming Ruby
cover_image:
excerpt: ""
category: ""
tags: [ruby, metaprogramming, book]
thumbnail: "http://johntopley.com/images/posts/2010/12/02/metaprogramming_ruby.jpg"
---

![](http://johntopley.com/images/posts/2010/12/02/metaprogramming_ruby.jpg)

> * [1. Object Model](#1.-object-model)
>	  * [What is inside a class](#what-is-inside-a-class)
>	  * [What happens when calling a method](#what-happens-when-calling-a-method)
> * [2. Methods](#2.-methods)
>	  * [Dynamic dispatch](#dynamic-dispatch)
>	  * [Dynamic define](#dynamic-define)
>	  * [`method_missing`](#method_missing)
>	  * [Dynamic proxy](#dynamic-proxy)
>	  * [Override `respond_to?`](#override-respond_to?)
>	  * [Recursive `method_missing` problem](#recursive-method_missing-problem)
>	  * [Blank Slate](#blank-slate)
> * [3. Blocks](#3.-blocks)
>	  * [Closure](#closure)
>	  * [Scope](#scope)
>	  * [`instance_eval`](#instance_eval)
>	  * [Callable object](#callable-object)
>	  * [Example: Create a DSL](#example:-create-a-dsl)
> * [4. Class definitions](#4.-class-definitions)
>	  * [`class_eval`](#class_eval)
>	  * [Singleton methods](#singleton-methods)
>	  * [Class macro](#class-macro)
>	  * [Eigenclass](#eigenclass)
>		* [Class Extension](#class-extension)
>		* [Object Extension](#object-extension)
>	  * [Alias](#alias)
> * [5. Code that writes code](#5.-code-that-writes-code)
> 	* [`Kernel#eval`](#kernel#eval)
>	  * [`Binding` class](#binding-class)
>	  * [`here` document](#here-document)
>	  * [Security issue](#security-issue)
>	  * [Hook method](#hook-method)
>	  * [Class extension mixins](#class-extension-mixins)

* * *

# 1. Object Model

Methods used for metaprogramming:

	Object.methods
	String.instance_methods
	Class.instance_methods(false) # non-inherited methods	superclass

Example:

	[].methods.grep /^re/ # list all the methods of Array starts with `re`

### What is inside a class

* `.class()`
* `.instance_variables()`
* `.methods()`

#### Path of Constants

{% highlight ruby %}
module M
  Y = 'a constant'
  class C
    ::M::Y
  end
end

M.constants # => [:C, :Y]
{% endhighlight %}

To get the full path:

{% highlight ruby %}
module M
  class C
    module M2
      Module.nesting # => [M::C::M2, M::C, M]
    end
  end
end

M.constants # => [:C, :Y]
{% endhighlight %}

### What happens when calling a method

1. Look for the method: in the __ancestors chain__, look for the method
2. Execute, with current `self` as scope

Try `MyClass.ancestors`

![](/images/blog/12-26-method-lookup.jpg)

#### `Kernel` module

`Kernel` has some private methods:

{% highlight ruby %}
>> Kernel.private_instance_methods.grep(/^pr/)
=> [:printf, :print, :proc]
{% endhighlight %}

__To add a method to `Kernel`__, an example from `RubyGems`:

{% highlight ruby %}
module Kernel
  def gem(gem_name, version_required)
    # ...
{% endhighlight %}

##### Some secret about `private` method 

This is the only way to call `private` method.

{% highlight ruby linenos %}
class A
  def public_method
    private_method

  end

  private
  def private_method
    p "private"
  end
end

A.new.public_method
{% endhighlight %}

__Add `self.` to line 3, it will fail__

Object can call private methods of superclass

Use `ancestors` method to track.

> 1.6 Quiz: Tangle of Modules

{% highlight ruby %}
module Printable
  def print
    p 'Printable#print'
  end

  def prepare_cover
    p 'Printable#prepare_cover'
  end
end

module Document
  def print_to_screen
    prepare_cover
    format_for_screen
    print
  end

  def format_for_screen
    p 'Document#format_for_screen'
  end

  def print
    p 'Document#print'
  end
end

class Book
  include Document
  include Printable
end

b = Book.new
b.print_to_screen

p Book.ancestors
{% endhighlight %}

Output:

	"Printable#prepare_cover"
	"Document#format_for_screen"
	"Printable#print"
	[Book, Printable, Document, Object, Kernel, BasicObject]

The reason to print `Printable#print` is that, `print` is send to `self` implicitly. From the ancestor chain, we can see `Book` -> `Printable`, and we found `print`.

![](/images/blog/12-26-printable.jpg)

# 2. Methods

> What's the difference between _static language_ and _dynamic language_?

### Dynamic dispatch

`.` to call a method, is actually calling `send` method. `obj.my_method(3)` = `obj.send(:my_method, 3)`

Example for `Test::Unit`, calling every test case method, which starts with `test`

{% highlight ruby %}
method_names = public_instance_methods(true)
tests = method_names.delete_if {|method_name| methdo_name !~ /^test./}
{% endhighlight %}

### Dynamic define

`Module#define_method()` can define a method

{% highlight ruby %}
class MyClass
  define_method :my_method do |my_arg|
    my_arg * 3
  end
end

obj = MyClass.new
obj.my_method(2) # => 6
{% endhighlight %}

`.methods.grep(regex)`

### `method_missing`

When a method is not found, Ruby will send this method as a symbol to `missiong_method`, like `nick.send :method_missing, :the_not_found_method_symbol`

Override `method_missing` can call some methods which do not exist.

{% highlight ruby %}

class Table
  def method_missing(id, *args, &block)
    return as($1.to_sym, *args, &block) if id.to_s =~ /^to_(.*)/
    return rows_with($1.to_sym => args[0]) if id.to_s =~ /^rows_with_(.*)/
    super
  end
end

# rows_with_country is valid
# to_csv is valid
{% endhighlight %}

#### example: dynamic getter and setter for undefined attributes, from _OpenStruct_

{% highlight ruby %}
class MyOpenStruct
  def method_missing(id, *args, &block)
    attribute = name.to_s
    if attribute =~ /=$/
      @attributes[attribute.chop] = args[0]
    else
      @attributes[attribute]
    end
  end
end
{% endhighlight %}

### Dynamic Proxy

#### `DelegateClass`

Delegate Class creates a new class from old one, and creates a `method_missing` in it, and redirect the call of its `method_missing` to the delegated class

{% highlight ruby %}
class Assistant
# ...
end

class Manager < DelegateClass(Assistant)
end
{% endhighlight %}

#### Refactored `Computer` class

{% highlight ruby %}
class Computer
  def method_missing(name, *args, &block)
    super if !@data_source.respond_to?("get_#{name}_info")
    info = @data_source.send("get_#{name}_info", argss[0])
    price = @data_source.send("get_#{name}_price", args[0])
    result = "#{name.to_s.capitalize}: #{info} ($#{price})"
    return " * #{result}" if price >= 100
    result
  end
end
{% endhighlight %}

If `get_#{name}_info` is not defined, then send to `super` and raise error.

else generate `info` and `price` and output `result`

### Override `respond_to?`

It sometimes lies. If a method defined in `method_missing`, then `respond_to?` will return wrong answer, which is a `false`

{% highlight ruby %}
def respond_to?
  @data_source.respond_to? "get_#{method}_info") || super
end
{% endhighlight %}

##### `const_missing`

Called when constant is missing.

### Recursive `method_missing` Problem

Undefined variable in `method_missing` will call `method_missing` again.

{% highlight ruby %}
class Roulette
  def method_missing(name, *args)
    person = name.to_s.capitalize
    3.times do
      number = rand(10) + 1
      p "#{number} ..."
    end
    "#{persom} got a #{number}"
  end
end
{% endhighlight %}

`number` cannot be found outside the `3.times` loop. It will call `self.number`, and then call `method_missing`, which becomes a recursive loop.

Solution is to add `number = ` before the loop.

### Blank Slate

__Best practise__: To avoid superclass has already defined the ghost method you defined in `method_missing`, remove the inherited ghost method, to avoid name conflict.

To remove method, use `Module#undef_method` (removes all the methods), or `Module#remoev_method` (remove receiver's method, keep inherited methods)

Ghost methods are slower than normal methods.

Do not remove methods start with `__`, `method_missing` or `respond_to?`, and leave some other methods.

{% highlight ruby %}
class Computer
  instance_merhods.each do |m|
    undef_method m unless m.to_s =~ /^__|method_missing|respond_to?/
  end

  # ...
end
{% endhighlight %}

# 3. Blocks

> Think about: How to use `yield`?

{% highlight ruby %}
def a_method(a,b)
  a + yield(a,b)
end
a_method(1,2) { |x,y| (x+y)*3 }
{% endhighlight %}

`Kernel#block_given?()` to check whether current method has a block to `yield`

{% highlight ruby %}
def a_method
  return yield if block_given?
  'no block'
end

a_method # => 'no block'
a_method { "Here is a block" } # => "Here is a block"
{% endhighlight %}

![](/images/blog/12-26-binding.jpg)

### Closure

Block is a complete program, can be executed immediately.

`Kernel#local_variables` can track local variables

### Scope

`Class.new` is an alternative to `class`

#### Scope gate

Program will create a new variable scope in 3 situations:

* starting new class definition, `class`
* starting new module definition, `module`
* start new method, `def`

Global variable can access any scope.

{% highlight ruby %}
@ var = "this is global top-level variable"

def my_method
  @var
end
{% endhighlight %}

#### Flattening the scope

_How to bypass scope gate?_

Use `Class.new` to replace `class`, `define_method` to replace`def`.

{% highlight ruby %}
my_var = "var"
MyClass = Class.new do
  puts "#{my_var} in class"
  define_method :my_method do
    puts "#{my_var} in method"
  end
end

MyClass.new.my_method

{% endhighlight %}

This technique is called __flatting the scope__.

#### Adding shared variable to methods

Use `send` instead of calling method directly.

Bypass `def` using shared variable.

{% highlight ruby %}
def define_methods
  shared = 0

  Kernel.send :define_method, :counter do
    shared
  end
  Kernel.send :define_method, :inc do |x|
    shared += x
  end
end

define_methods

counter
inc(4)
counter
{% endhighlight %}

`Kernel#counter` and `Kernel#inc` are sharing `shared` now.

#### To transpass scope gate, use method call instead of `class`, `module` and `def` keywords

### `instance_eval`

Things passed into `instance_eval` is __context probe__.

`instance_exec` allow parameters

{% highlight ruby %}
class C
  def initialize
    @x, @y = 1, 2
  end
end

C.new.instance_exec(3) {|arg| (@x + @y) * arg }
{% endhighlight %}

#### Clean Rooms

A place to just run block, does not affect to current environment.

### Callable object

#### `Proc` object

Proc: convert block to object

* `Proc.new`
* `Proc::lambda` (Kernel method)
* `proc` (Kernel method)

`dec = lambda { |x| x - 1 }`

##### `&` operator

When using `yield`

1. you want to pass the block to another method
2. you want to convert the block to a Proc

Then you need to mark this block variable using `&`

{% highlight ruby %}
def my_method(&the_proc)
  the_proc
end

p = my_method { |name| "Hello, #{name}" }
puts p.call("world")
{% endhighlight %}

Use `&` to convert `Proc` to block.

{% highlight ruby %}
def my_method(greeting)
  puts "#{greeting} #{yield}"
end

my_proc = proc { "world" }
my_method("Hello", &my_proc)
{% endhighlight %}

`my_proc` can be yield.

#### `lambda` and `proc` difference

##### 1. The meaning of `return` is different.

* `lambda` returns value from the proc
* `proc` returns(procedurely) from the code block

{% highlight ruby %}
def double
  p = Proc.new { return 10 }
  return 20 # unreachable code
end
{% endhighlight %}

Correct way

{% highlight ruby %}
def double
  p = Proc.new { 10 }
  return 20 # unreachable code
end
{% endhighlight %}

##### 2. Number of arguments

If a `proc` has 2 arguments

* if defined using `lambda`, it only accept 2 arguments. No more, no less, otherwise program will fail
* if defined using `proc` or `Proc`, it will ignore redundant arguments, the non-passed arguments are defined as `nil`

##### Best practise

If you can use `lambda`, then use `lambda`

#### `Kernel#proc`

* In Ruby 1.8, it is alias of `Kernel#lambda`
* In Ruby 1.9, it is alias of `Proc.new`

#### Method is also callable object, like `lambda`

Method can be detached and re-attached.

{% highlight ruby %}
unbound = m.unbound # m is a method object
another_obj = MyClass.new
m = unbound.bind(another_obj)
m.call

{% endhighlight %}

Method can be binded to an object and run. But `lambda` is a closure. It does not require to be binded.

### Example: Create a DSL

{% highlight ruby %}
def event(name, &block)
  @events[name] = block
end

def setup(&block)
  @setups << block
end

Dir.glob('*events.rb').each do |file|
  @setups = []
  @events = []
  load file
  @events.each_pair do |name, event|
    env = Object.new
    @setups.each do |setup|
      env.instance_eval &setup
    end
    p "ALERT: #{name}" if env.instance_eval &event
  end
end
{% endhighlight %}

The DSL file ends with `*events.rb`:

{% highlight ruby %}
event 'the sky is falling' do
  @sky_height < 300
end

event "It's getting closer" do
  @sky_height = 100
end

setup do
  @sky_height = 100
end

setup do
  @mountains_height = 200
end

{% endhighlight %}

Refactor: eliminate global variables `@events` and `@setups`

{% highlight ruby %}
lambda {
  setups = []
  events = []

  Kernel.send :define_method, :event do |name, &block|
    events[name] = block
  end

  Kernel.send :define_method, :setup do |&block|
    setups << block
  end

  Kernel.send :define_method, :each_event do |&block|
    events.each_pair do |name, event|
      block.call name, event
    end
  end

  Kernel.send :define_method, :each_setup do |&block|
    setups.each do |setup|
      block.call setup
    end
}.call

Dir.glob('*events.rb').each do |file|
  @setups = []
  @events = []
  load file
  @events.each_pair do |name, event|
    env = Object.new
    @setups.each do |setup|
      env.instance_eval &setup
    end
    p "ALERT: #{name}" if env.instance_eval &event
  end
end
{% endhighlight %}

The starting `lambda` defines all the DSL methods. THe point is, the DSL methods are sharing local variables `events` and `setups`.

# 4. Class definitions

### `class_eval`

Run a block within current class

{% highlight ruby %}
def add_method_to(a_class)
  a_class.class_eval do
    def m; 'Hello!'; end
  end
end

add_method_to String
'abc'.m # => "Hello"
{% endhighlight %}

* `instance_eval` modifies `self`
* `class_eval` modifies current class and `self`

When defining class, `self` means current `Class` object
You can use variable outside of scope

### Singleton methods

Method effective on single object.

{% highlight ruby %}
str = ""

def str.title?
  self.upcase == self
end

str.title?
str.singleton_methods
{% endhighlight %}

Static method in Ruby defined as `def self.method`. This is actually a singleton method of the `Class` object.

Another way to define singleton method (class method)

{% highlight ruby %}
def Myclass.my_class_method; end
{% endhighlight %}

### Class macro

An example: `attr_accessor`, `attr_reader`. These are class macros.

All the `attr_*` are defined in `Module` class.

Write your own class macro.

Here is an example of deprecate old methods, print wawrning message when being called.

{% highlight ruby %}
class Book
  def self.deprecate(old_method, new_method)
    warn "Warning: #{old_method}() is deprecated. Use #{new_method}()"
    send(new_method, *args, &block)
  end

  # ...
end

deprecate :GetTitle, :title
deprecate :title2, :subtitle
{% endhighlight %}

### Eigenclass

A hidden class on the ancestors chain.

Eigenclass is a singleton class object. It stores the singleton method of an object. It is the same usage of `instance_eval`.

To access eigenclass:

{% highlight ruby %}
obj = Object.new
eigenclass = class << obj
  self
end

eigenclass.class # => Class
{% endhighlight %}

An helper method to get eigenclass object:

{% highlight ruby %}
class Object
  def eigenclass
    class << self
      self
    end
  end
end

"abc".eigenclass # => #<Class:#<String:0x123456>>
{% endhighlight %}

To define method in eigen class:

{% highlight ruby %}
class MyClass
  class << self
    def my_method; end
  end
ed
{% endhighlight %}

Use __eigenclass__ is better than define methods using class name, because it is better for future refactoring.

![](/images/blog/eigenclass.jpg)

__Add attribute to class, using eigenclass__:

{% highlight ruby %}
class MyClass
  class << self
    attr_accessor :c
  end
end

MyClass.c = "It works"
{% endhighlight %}

#### Class Extension

{% highlight ruby %}
module MyModule
  def self.my_method; 'hello'; end
end

class MyClass
  include MyModule
end

MyClass.my_method # NoMethodwError!
{% endhighlight %}

To access my_method as a class method, include `MyModule` in `MyClass`'s eigenclass

{% highlight ruby %}
module MyModule
  def self.my_method; 'hello'; end
end

class MyClass
  class << self
  include MyModule
  end
end

MyClass.my_method # NoMethodwError!
{% endhighlight %}

#### Object Extension

{% highlight ruby %}
module MyModule
  def my_method; 'hello'; end
end

obj = Object.new
class << obj # extends obj
  include MyModule
end

obj.my_method # => "hello"
obj.singleton_methods # => [:my_method]
{% endhighlight %}

__Another way to extend object__

{% highlight ruby %}
module MyModule
  def my_method; 'hello'; end
end

obj = Object.new
object.extend MyModule
obj.my_method # => "hello"

class MyClass
  extend MyModule
end
MyClass.my_method # => "hello"

{% endhighlight %}

### Alias 

{% highlight ruby %}
def my_method; 'my_method()'; end
alias :m, :my_method
{% endhighlight %}

Link `alias` after defining the method.

#### Around Alias: Example from `RubyGems`

{% highlight ruby %}
module Kernel
  alias gem_original_require require

  def require(path)
    gem_original_require path
  rescue LoadError => load_error
    # if old require() cannot locate the file, then use new require()
    # ...
  end
end
{% endhighlight %}

__Bad Thing__: you cannot load around alias twice, otherwise program will crash.

##### Another example: Amazon

To override Amazon's `reviews_of`:

{% highlight ruby %}
class Amazon
  alias :old_reviews_of, :reviews_of # make alias of old method

  def reviews_of # define new method, override
    # ...
  end
end
{% endhighlight %}

##### Another example: operator override

{% highlight ruby %}
class Fixnum
  alias :old_plus :+
  def +(value)
    self.old_plus(value).old_plus(1)
  end
end
{% endhighlight %}

# 5. Code that writes code

The meaning of `meta` is to code using code.

### `Kernel#eval` 

It uses string to eval:

{% highlight ruby %}
array  = [10, 20]
element = 30
eval "array << element" # => [10, 20, 30]
{% endhighlight %}

#### Example from Capistrano

{% highlight ruby %}
map = {} # a hash

map.each do |old, new|
  # ...
  eval " task #{old.inspect} do
    warn \"[DEPRECATED] `#{old}' is deprecated. Use `#{new}' instead.\"
    find_and_execute_task #{new.inspect}
  end"
end
{% endhighlight %}

### `Binding` class 

`Kernel#binding` object represents a variable scope.

{% highlight ruby %}
class MyClass
  def my_method
    @x = 1
    binding
  end
end

b = MyClass.new.my_method # returns the binding
{% endhighlight %}

For `*eval()` methods, you can pass a `Binding` object as parameter. Then code of `eval` will execute in scope.

	eval "@x", b # => 1

A pre-defined constant `TOPLEVEL_BINDING`

	eval "@x", TOPLEVEL_BINDING

Binding is a cleaner scope.

### `here` document 

For define multiple lines string

{% highlight ruby %}
s = <<END
  # some code ...
END

p s
{% endhighlight %}

### Security issue 

To prevent `eval` problem, use dynamic dispatch to replace `eval`

{% highlight ruby %}
def explore_array(method, *args)
  ['a', 'b', 'c'].send(method, *args)
end

def explore_array_eval(method)
  code = "['a', 'b', 'c'].#{method}"
  eval code
end
{% endhighlight %}

#### Security level

Ruby has security level. `0` is the most unsecure. `4` is highest security. `1 -> 4` does not allow running tained code. You need to `untaint` a string before `eval`.

{% highlight ruby %}
user_input = "User input: #{gets()}"
puts user_input.tainted?

> x=1
> => true

{% endhighlight %}

#### `Kernel#load` and `Kernel#require`

`load` runs the code from file

`require` is the normal require

#### Create sandbox to run `eval`: example from ERB

{% highlight ruby %}
class ERB
  def result(b=TOPLEVEL_BINDING)
    if @safe_level
      proc {
        $SAFE = @save_level
        eval(@src, b, (@filename || '(erb)'), 1)
      }.call
    else
      eval(@src, b, (@filename || '(erb)'), 1)
    end
  end
end
{% endhighlight %}

#### Notice

* `class_eval` does not accept variable is class name. Should use `eval` instead.
* `class_eval` does not accept `def` method with variable. Use `define_method()` instead.

### Hook method

The method being called when event triggered, like `Module#included`, `Class#inherited`

{% highlight ruby %}
class String
  def self.inherited
 	 # ...
  end
end
{% endhighlight %}

`Class#inherited` is called when some class inherited from `String`.

Other hook method:

* `Module#included`
* `Module#extend_object`: called when extending class
* `Module#method_added`

Override `Module#include`

{% highlight ruby %}
class C
  def self.include(*modules)
    p "Called: C.include #{module}"
    super
  end
end
{% endhighlight %}

### Class extension mixins

__Class extension__ with __Hook method__ technique.

1. Define a module, eg. `MyMixin`
2. Define a inner module
3. Override the `MyMixin#included()` to extend the class includes the module

{% highlight ruby %}
module MyMixin
  def self.included(base)
    base.extend(self)
  end

  def x
    "x()"
  end
end
{% endhighlight %}
