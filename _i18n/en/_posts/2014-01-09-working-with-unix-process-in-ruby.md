---
layout: post
title: "Working with Unix Process in Ruby"
subtitle: 
cover_image: 
excerpt: "NOTES of Working with Unix Process in Ruby, by Jesse Storimer"
category: ""
tags: [book, ruby, process, unix]
thumbnail: "http://rayhightower.com/images/working-w-unix-processes.jpg"
draft: 
---

![](http://rayhightower.com/images/working-w-unix-processes.jpg)

[Book home page](http://www.jstorimer.com/products/working-with-unix-processes)

## Reference of Ruby Process related methods

Ruby Library Method | Unix System Method | Description
--- | --- | ---
`Process.pid` | `getpid` | get calling process identification
`Process.ppid` | `getppid` | get parent process identification
`IO#fileno` | | get file descriptor number 
`Process.getrlimit` | `getrlimit` | get system resource limit
`Process.setrlimit` | `setrlimit` | set system resource limit
 - | `setenv` | set environment variable
 - | `getenv` | get environment variable value
 `Kernel#exit` | `exit` | exit program
 `Kernel#abort` | | exit, and message print to STDERR
 `Kernel#raise` | | like `raise` in ruby, look for exception handling. Exit if not found.
 `Kernel#fork` | `fork` | 
 `Process#wait` | `waitpid` | wait until one of the child processes exit
 `Process#wait2` | `waitpid` | returns (pid, status)
 `Process#waitpid`| `waitpid` | Ruby: wait for process
 `Process#waitpid2` | `waitpid` | Ruby: wait for process, returns 
 `Process#detach` | - | create a new process, only to wait for a centain process to end
 `Process#kill` | `kill` | 
 `Process#trap` | `sigaction` | define signal handling function
 `IO.pipe` | `pipe` | define new pipe
 `Socket.pair` | `socketpair` | define pair of sockets
 `Socket.recv` | `recv` | sockets receive
 `Socket.send` | `send` | sockets send
 `Process.setsid` | `getsid` | create new session group
 `Process.getpgrp` | `getpgrp` | get process group id

# 1. Basic of Process

* Get process descriptor in shell: `$$`
* In Unix, everything is FILE. Every file gets a descriptor
* Get process name in ruby: `$PROGRAM_NAME`

#### File descriptor

1. File descriptor number is resuable
2. STDIN, STDOUT, STDERR is predefined

{% highlight ruby %}
puts STDIN.fileno 	# => 0puts STDOUT.fileno 	# => 1puts STDERR.fileno 	# => 2
{% endhighlight %}

#### `IO` library in Ruby

`open`, `close`, `read`, `write`, `pipe`, `fsync`, `stat`

#### Resource Limitation of Process

Maximum file descriptor number: `p Process.getrlimit(:NOFILE) # => [2560, 9223372036854775807]`

2560 is __Soft limitation__. To change the sofr limitation, eg. `Process.setrlimit(:NOFILE, 4096)`. Third argument of this method can set hard limitation. It is not reversable.

#### Environment and arguments

* `ENV`: get environment argument into an array in Ruby
* `ARGV`: get arguments from the command line into an array in Ruby

A ruby library `optparse` is used for parsing command line options.

#### Exit code

`exit`, `abort`, `raise`

### Examples of process basic

{% highlight ruby %}
# IO#fileno
passwd = File.open('/etc/passwd' )puts passwd.fileno# Resource limitationsProcess.getrlimit(:NPROC )Process.getrlimit(:FSIZE )Process.getrlimit(:STACK )
{% endhighlight %}

# 2. Multiple processes: `fork`

Child process will inherit the whole memory of parent process. To improve performance, memory uses _copy-on-write_ strategy.

__IMPORTANT__: `fork` returns `nil` in child process, returns the pid of child process in parent process.

### Process Wait

`Process#wait`, `Process#wait2`, `Process#waitpid`, `Process#waitpid2`

`wait` and `waitpid` are actually the same. They accepts the same type of arguments, and behave the same.

Pass argument `-1` to `wait` will wait for any child process.

If there is no child process, `Process.wait` will throw `Errno::ECHILD` exception.

### Zombie process

The kernel will retain the status of exited child processes until the parent process requests that status using `Process.wait`. If the parent never requests the status then the kernel can never return that status information.

`Process.detach` will create a process wating for specified child process to exit.

Using `ps` to check process, zombie process will be marked `z` or `Z+`

### Code example of `fork`

{% highlight ruby %}
# Fork a process
if fork
  ...
else
  ...
end
# or
fork do 
  ...
end

# wait2
pid, status = Process.wait2

# waitpid2
favorite = fork do; exit 77; end
pid, status = Process.waitpid2 favorite
puts status.exitstatus	

# zombie process
pid = fork do
  # ...
end
Process.detach(pid)

{% endhighlight %}

# 3. Signal

`wait` is a __blocking method__: until child process exit, the method returns.

Catching signal is non-blocking.

Signal delivering is not reliable. 

We suggest using `Process.wait` to deal with signal. 

	Process.wait(-1, Process::WNOHANG)
	
`Process::WNOHANG` means, if no child process exit, then do not block.

#### Catch signal

#### Send signal

	Process.kill(:INT, pid_of_a_process)

#### Re-define signal handling process

	trap(:INT) { ... }
	
But some of the signal handling cannot be re-defined.

`INT` is actually `Ctrl+C`, which is not as powerful as `KILL`.

#### Re-define signal propertly

__Notice__ to Keep system default handling

{% highlight ruby %}
trap(:INT) { puts 'This is the first signal handler' }old_handler = trap(:INT) {  old_handler.call  puts 'This is the second handler'  exit}sleep
{% endhighlight %}

Also we can use `at_exit` hook.

### Example of Signal

{% highlight ruby %}
# catch SIGCHLD
trap(:CHLD) do
  ...
end

# Full example
child_processes = 3
dead_processes = 0

child_processes.times do
  fork do
    sleep 3
  end
end

# To ensure CHLD will not call flush for #puts call
$stdout.sync = true

trap(:CHLD) do
  begin
    while pid = Process.wait(-1, Process::WNOHANG)
      puts pid
	  dead_processes += 1
	  exit if dead_processes == child_processes
    end
  rescue Errno::ECHILD
  end
end

loop do
  (Math.sqrt(rand(44)) ** 8).floor
  sleep 1
end
{% endhighlight %}

# 4. Pipe

Pipe is a single direction data stream.

#### Shared pipe in multi-processes

`IO` operations: `read`, `write`, `close`, `gets`, `puts`

Stream is endless. It has protocol specified _delimeter_ to define _chunks_. `gets`, `puts` can R/W a string seperated by `newline` sign. `newline` is a delimeter.

IPC (Inter-process communication) uses _sockets_, rather than TCP, because sockets is faster in IPC.

Sockets uses _datagram_ to communicate rather than stream. Datagram is a full piece of message, not using delimeter.

### Example of Pipe

{% highlight ruby %}
reader, write = IO.pipe

# basic communication
reader, writer = IO.pipewriter.write("Into the pipe I go...")writer.close # close unused stream endpointputs reader.read

# shared pipe
reader, writer = IO.pipefork do  reader.close10.times dowriter.puts "Another one bites the dust"end endwriter.closewhile message = reader.gets  $stdout.puts messageend
# Socketsrequire 'socket'Socket.pair(:UNIX, :DGRAM, 0) #=> [#<Socket:fd 15>, #<Socket:fd 16>]

# Full example of sockets
require 'socket'child_socket, parent_socket = Socket.pair(:UNIX, :DGRAM, 0)maxlen = 1000fork do  parent_socket.close  4.times do    instruction = child_socket.recv(maxlen)    child_socket.send("#{instruction} accomplished!", 0)end endchild_socket.close2.times do  parent_socket.send("Heavy lifting", 0)end2.times do  parent_socket.send("Feather lifting", 0)end4.times do  $stdout.puts parent_socket.recv(maxlen)	end
# OUTPUT# Heavy lifting accomplished!# Heavy lifting accomplished!# Feather lifting accomplished!# Feather lifting accomplished!

{% endhighlight %}

# 5. Daemon Process

Daemon process normally won't stop by itself.

When system boots, there is a `init` process, whose ppid is __0__. It is the ancestor of all processes.

#### Create a daemon process

`exit if fork` or `Process.daemon`. In parent process, it returns the pid of child, which leads to exit.

After parent exit, the `ppid` of orphan process is always __1__.

#### Process group & Session group

Use `Process.setpgrp(new_group_id)` to set process group.

Process group id is the pid of the group leader process.

A child process has the same process group id as the parent process.

Terminal receives signal, and dispatches to every child processes in this process group.

__Session group__ is a set of process groups.

	git log | grep shipped | less
	
In this example, every sub-command has its own process group. They all belongs to the same session group.

When signal comes to the leader of the session group, it passes the signal to all the leaders of the process groups inside, and the leaders pass the signal again to processes in the process group.

Hierarchical signal passing.

`Process.setsid` to get session group id. It can also fork a new process group and a new leader of session group.

After that if we run `exit if fork`, the new session group leader will leave the control of terminal. The new session group can be used as daemon processes.

Also set the streams of the process to `/dev/null`.

	STDIN.reopen "/dev/null"	STDOUT.reopen "/dev/null", "a"	STDERR.reopen "/dev/null", "a"

### Examples of daemon process

{% highlight ruby %}
# process group id
puts Process.pidputs Process.getpgrpfork {  puts Process.pid  puts Process.getpgrp}

{% endhighlight %}

# 6. Spawning terminal process

`exec` command can convert current process to another process, unrevertable.

Use `fork + exec` to spawn new process. `exec` cannot convert a process back. But with `fork` can maintain a unconverted copy of process.

{% highlight ruby %}
hosts = File.open('/etc/hosts')exec 'python', '-c', "import os; print os.fdopen(#{hosts.fileno}).read()"
{% endhighlight %}

`exec` runs a shell command actually. 

`Kernel#system` runs shell command, and returns the terminal exit code.

`` Kernel#` `` returns the STDOUT string. Same as `%x[]`

{% highlight ruby %}
`ls``ls --help`%x[git log | tail -10]
{% endhighlight %}

`Process.spawn` is a non-blocking call.

#### `IO.popen`

`popen` opens a pipe, returns file descriptor number.

#### `IO.open3`

Opens STDIN, STDOUT, STDERR at the same time.

#### Last word about `fork`

`fork` consumes a lot of memory. Some system call have optimization. Original Ruby library does not support system call, but `posix-spawn` project supports.

### Example of spawn

{% highlight ruby %}
Process.spawn({'RAILS_ENV' => 'test'}, 'rails server')Process.spawn('ls', '--help', STDERR => STDOUT)

# example of popen
IO.popen('less', 'w') { |stream|  stream.puts "some\ndata"}
# example of open3
require 'open3'Open3.popen3('grep', 'data') { |stdin, stdout, stderr|  stdin.puts "some\ndata"  stdin.close  puts stdout.read}Open3.popen3('ls', '-uhh', :err => :out) { |stdin, stdout, stderr|  puts stdout.read}

{% endhighlight %}

