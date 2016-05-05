---
layout: post
title: "Ruby Gems Installation Troubleshoting"
subtitle: 
cover_image: 
excerpt: "Nokogiri, Imagemagick"
category: ""
tags: [mac, ruby]
thumbnail: "http://upload.wikimedia.org/wikipedia/commons/0/0d/Imagemagick-logo.png"
draft: 
---

## RMagick

	brew install imagemagick
	
	find /usr -name MagickWand.h
	
Then I encounter this:

	2 warnings generated.
	linking shared-object RMagick2.bundle
	ld: file not found: /usr/local/lib/libltdl.7.dylib for architecture x86_64
	clang: error: linker command failed with exit code 1 (use -v to see invocation)
	make: *** [RMagick2.bundle] Error 1
	
The solution is something like this:

	cd /usr/local/Cellar/imagemagick/6.8.0-10/lib/
	ln -s libMagick++-Q16.7.dylib   libMagick++.dylib
	ln -s libMagickCore-Q16.7.dylib libMagickCore.dylib
	ln -s libMagickWand-Q16.7.dylib libMagickWand.dylib
	gem install rmagick

It works for me

* [http://blog.hostonnet.com/cant-install-rmagick-2-13-2-cant-find-magickwand-h]()
* [https://coderwall.com/p/mwtoya]()
* [https://github.com/rmagick/rmagick/issues/80]()

## nokogiri

__Problem:__ 

	libiconv is missing.  please visit http://nokogiri.org/tutorials/installing_nokogiri.html for help with installing dependencies.

__Solution:__

Install `libiconv` first, using __brew__

Then do sth like this: 

	gem install nokogiri -- --with-iconv-dir=/usr/local/Cellar/libiconv/1.13.1