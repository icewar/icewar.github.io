---
layout: post
title: "CSS trick: float, overflow, clear"
subtitle: 
cover_image: 
excerpt: 
category: 
tags: [web, css, frontend]
---

The float and clear problem confuses many web developers.

Suppose we have a layout like this:

{% highlight html %}
<style>
body{
    width:700px;
}
 
.left {
    width:300px;
    height: 200px;
    float: left;
    background-color: red;
}
.right {
    width:300px;
    height: 200px;
    float: right;
    background-color: yellow;
}
.wrapper {
    background-color: blue;
}
</style>
<body>
<div class="wrapper">
    <div class="left"></div>
    <div class="right"></div>
</div>
</body>
{% endhighlight %}

What will happen it that the wrapper will not contain the two divs. Check out yourself by set the background color of wrapper.

There are several ways to fix this.

## First way: clear: both

Add this code to the css:

{% highlight css %}
.clear {
    clear: both;
} 
{% endhighlight %}

And add this below the `.right div`:

{% highlight html %}
<div class="clear"></div>
{% endhighlight %}

The reason is that, if at the bottom, there are many `div`s floated inside a wrapper `div`, then these floated `div`s will not extend the height(size) of the wrapper `div`. Adding a clear `div` at the bottom, with `clear: both`, which means nothing allows to be floated on neither sides of it, solves the problem.

## Second way: overflow

Back to original layout. We can add another style to the wrapper `div`:

{% highlight css %}
overflow: auto;
{% endhighlight %}

This means, if anything `div`s inside exceed the width or height, there will be a scroll bar.

If overflow is set to `hidden`, it will not display the exceeding part. But `hidden` also works for this problem.

## Third way: clearfix

In the first way, adding a meaningless `div` at the end of wrapper is a bad programming habit. To avoid this, here comes clearfix trick.

Add this to the style:

{% highlight css %}
.clear::after { // :psuedo-class ::psuedo-element
    // after means the at end of a element, not really after the element
 
    content: ":)"; // anything is ok
    clear: both;
    display:block;
    visibility: hidden;
    height:0px;
}
{% endhighlight %}

Apply clear to `wrapper div`:

{% highlight html %}
<div class="wrapper clear">
    <div class="left"></div>
    <div class="right"></div>
</div>
{% endhighlight %}

This code means, with a clear class, an element will have a block at the end of the element. If you apply `clear` to a `div`, then it will have a block at the end of the `div`. This `div` has content, clear both left and right, like in the first way. It will display as a block, which by default is `auto`. The block will not be visible, but it exists. The `height` is 0px, so it will not take up space. We don’t need to put a clear div using HTML at the end of the element. Code is clean. Yeah.
