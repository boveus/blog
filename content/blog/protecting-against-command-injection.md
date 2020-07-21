---
title: "Protecting Against Command Injection"
date: 2020-07-19
slug: "protecting-against-command-injection"
description: "Protecting against Command Injection - a practical example of secure coding in Ruby on Rails from the Redmine project."
keywords: ['command injection', 'security', 'secure coding', 'command injection protection']
draft: false
tags: []
math: false
toc: false
---

In this post I will to walk through a few areas of the [Redmine](https://github.com/redmine/redmine) application and analyze how the authors of this application protected it against command injection vulnerabilities.  I will also provide some general recommendations for how to safely call bash or other system calls in your own code.

## What is command injection?

Command injection is a type of injection vulnerability which is #1 in the OWASP top 10 vulnerabilities.  It is a vulnerability which can allow an attacker to execute arbitrary system commands.

#### [Mitre](https://cwe.mitre.org/data/definitions/77.html) says the following about command injection vulnerabilities
> Command injection vulnerabilities typically occur when:
> 1. Data enters the application from an untrusted source.
> 2. The data is part of a string that is executed as a command by the application.
> 3. By executing the command, the application gives an attacker a privilege or capability that the attacker would not otherwise have.

## Defending against command injection
[OWASP recommends](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) the following strategies to defend against command injections:
 1. Avoid calling OS commands directly and use language APIs instead.
 2. Escape values added to OS commands specific to each OS
 3. Parameterization to enforce seperation between the data and the command
 4. Input Validation

As we will see below, Redmine makes use of the third and fourth OWASP recommendations to defend their application.

## Analysis of Redmine

Redmine is a popular open-source project management tool written in Ruby on Rails.  It provides extensive functionality to interface with Source Control Management (SCM) tools such as Git, Subversion and Mercurial.  It allows users to use a GUI to create, modify, delete, and get information about various SCM repositories.  

In order to support this functionality, the application is required to make various system level command calls.  If these features are not implemented properly, they can leave an application vulnerable to a Remote Command Execution vulnerability.

## Brakeman scan of Redmine
One of the first steps when analyzing a Ruby on Rails application for a vulnerability is to use [Brakeman](https://brakemanscanner.org/).  Brakeman is a powerful, open source static code analysis tool and can often detect potential vulnerabilities in a Rails application.

Among other warnings, Brakeman produced the following warning related to a potential `Command Injection` vulnerability in the `abstract_adapter.rb` file.  At first glance this looks like a vulnerable implementation of the `IO.popen` method.

```shell
Confidence: Medium
Category: Command Injection
Check: Execute
Message: Possible command injection
Code: IO.popen("#{cmd} 2>>#{shell_quote(stderr_log_file)}", "r+")
File: lib/redmine/scm/adapters/abstract_adapter.rb
Line: 247
```
Let's walk through this code and see if an attacker could potentially abuse this functionality.

## AbstractAdapter

It looks like the call to `IO.popen` is inside the `shellout` in the `AbstractAdapter` class:


```ruby
def shellout(cmd, options = {}, &block)
    ...
    begin
      mode = "r+"
      IO.popen(cmd, mode) do |io|
        io.set_encoding("ASCII-8BIT") if io.respond_to?(:set_encoding)
        io.close_write unless options[:write_stdin]
        yield(io) if block_given?
      end
    ...
end
```

It looks like this method simply receives the `cmd` variable and passes it to `IO.popen`.  So far there is no sanitization against the `cmd` variable.  The `AbstractAdapter` is a superclass for various adapters that Redmine uses to process SCM commands to various VCS systems.  We will need to look at some of the subclasses to find where `shellout` is called.

## GitAdapter

Within the `GitAdapter` subclass, which inherits from the `AbstractAdapter` superclass, there are only two calls to `shellout`.  One of these is in the `git_cmd` method:

```ruby
def git_cmd(args, options = {}, &block)
  repo_path = root_url || url
  full_args = ['--git-dir', repo_path]
  if self.class.client_version_above?([1, 7, 2])
    full_args << '-c' << 'core.quotepath=false'
    full_args << '-c' << 'log.decorate=no'
  end
  full_args += args
  ret =
    shellout(
      self.class.sq_bin + ' ' + full_args.map {|e| shell_quote e.to_s}.join(' '),
      options,
      &block
    )
  if $? && $?.exitstatus != 0
    raise ScmCommandAborted, "git exited with non-zero status: #{$?.exitstatus}"
  end

  ret
end
```

There is a lot going on here, but it seems that the `args` argument is appended to the `full_args` array, which is appended to the value of `sq_bin`.  The `full_args` is mapped over and the `shell_quote` method is used against each element, and they are joined by a space.

`sq_bin` is not able to be controlled by a user and will be `git`, unless otherwise specified in a configuration file.

```ruby
class GitAdapter
  def sq_bin
   @@sq_bin ||= shell_quote_command
  end

  GIT_BIN = Redmine::Configuration['scm_git_command'] || "git"

  def client_command
    @@bin    ||= GIT_BIN
  end
...
class AbstractAdapter
  def shell_quote_command
    Redmine::Utils::Shell.shell_quote_command client_command
  end
...
```

The `shellout` call ends up looking like this:
```ruby
shellout(
  'git' + ' ' + '--git-dir' + ' ' + repo_path + ' ' + shellquote(arg[0].to_s) + ' ' + shellquote(arg[1].to_s)
)
```
Each user-controlled parameter is passed to the `shellquote` method before being passed to the `shellout` method

## Utils

Looking further through the codebase, it appears that the `shell_quote` method is defined in the `Utils` module and is what is actually used here to provide protection against command injection.

```Ruby
  def shell_quote(str)
    if Redmine::Platform.mswin?
      '"' + str.gsub(/"/, '\\"') + '"'
    else
      "'" + str.gsub(/'/, "'\"'\"'") + "'"
    end
  end
```

This method receives a string and, depending on the OS, escapes certain quote characters.  It wraps the full string in double quotes in Windows and single quotes in other OSes (Linux for example).  

It seems that this particular area of the code even if we can control the input will have a limited potential for being exploited.

For example, a command injection attack would involve the addition of an argument that can allow for an arbitrary command of some kind such as `;`, `|`, or `>>`.  In code that is vulnerable to command injection it would produce a command like the following:
```shell
git branch branch-name|touch haxxed.txt
```
This command would result in unintended behavior since the attacker is able to execute an arbitrary command using the `|` operator.

This command, however, does not permit parameter expansion and the quoted string is interpreted as a single argument.  

```shell
git branch 'branch-name|touch haxxed.txt'
```

This is a good example of OWASP's recommendation regarding the separation between the data and the command.  In this case, the data (the branch name) is separated from the command, `git branch`.  This leaves a potential attacker with no obvious way of manipulating the `command` being called, even though they could manipulate the `data` that is being passed to the command.

### Why does the quote work here?
[GNU](https://www.gnu.org/software/bash/manual/html_node/Quoting.html) offers the following information about quoting shell commands:

  Quoting is used to remove the special meaning of certain characters or words to the shell. Quoting can be used to disable special treatment for special characters, to prevent reserved words from being recognized as such, and to prevent parameter expansion.


## SubversionAdapter

Another interesting method exists in the `SubversionAdapter` class.  At first glance this code also seemed to be vulnerable, but further inspection shows that it is not.

```ruby
  def entries(path=nil, identifier=nil, options={})
    path ||= ''
    identifier = (identifier and identifier.to_i > 0) ? identifier.to_i : "HEAD"
    entries = Entries.new
    cmd = +"#{self.class.sq_bin} list --xml #{target(path)}@#{identifier}"
    cmd << credentials_string
    shellout(cmd) do |io|
      ...
  end
```

This code also receives user controlled input in the form of the `path` and `identifier` arguments.  On the second line of this method uses a ternary statement to either coerce the argument into an integer, using `.to_i`, or to set that value to `HEAD`.  This means that the `identifier` is likely not a vector for attack here.

This is an example of OWASP's recommendation regarding `input validation`.  In this case, the attacker can only pass an integer here, so there is also a very limited potential attack vector here.

The `path` variable is interesting, though.  It seems that it is passed to the `target` method and then interpolated here.

Looking in the `AbstractAdapter`, the `path` method is defined here:
```ruby
def target(path, sq=true)
  path ||= ''
  base = /^\//.match?(path) ? root_url : url
  str = "#{base}/#{path}".gsub(/[?<>\*]/, '')
  if sq
    str = shell_quote(str)
  end
  str
end
```

It looks like we see the `shell_quote` method is also used here. Since the `sq` argument defaults to `true`, the `entries` method in the subversion adapter is also not vulnerable.

## Protecting against Command Injection attacks

As we saw above, the Redmine application implemented the following strategies to protect against Command injection:
1. Parameterization to enforce separation between the data and the command
2. Input Validation

If you *have* to call a command directly, ensure that you separate the `data` from the `command`.  This is accomplished by wrapping the `data` in quotes.  You should also ensure that any data that is not separated is validated or sanitized in some way before being passed to the system call.
