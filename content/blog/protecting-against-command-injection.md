---
title: "Protecting Against Command Injection"
date: 2020-07-16
slug: "protecting-against-command-injection"
description: "Protecting against Command Injection - a practical example of secure coding in Ruby on Rails from the Redmine project."
keywords: ['command injection', 'security', 'secure coding', 'command injection protection']
draft: true
tags: []
math: false
toc: false
---

Portswigger recommends not using system commands at all to prevent this sort of attack: https://portswigger.net/web-security/os-command-injection

In this post I am going to discuss one of the OWAP top 10 vulnerabilities. I am going to walk through the [Redmine)](https://github.com/redmine/redmine) application and how the authors of this application protected it against command injection.  I will also provide some general recommendations for how to safely call bash or other system calls in your own code.

## What is command injection?

Command injection is a type of injection flaw, which is #1 of the OWASP top 10 vulnerabilities.  It is a vulnerability which can allow an attacker to execute arbitrary system commands.

#### [Mitre](https://cwe.mitre.org/data/definitions/77.html) defines it as
> Command injection vulnerabilities typically occur when:
> 1. Data enters the application from an untrusted source.
> 2. The data is part of a string that is executed as a command by the application.
> 3. By executing the command, the application gives an attacker a privilege or capability that the attacker would not otherwise have.


## Brakeman scan of Redmine

One of the first steps when analyzing a Rails application for a vulnerability, is to use [Brakeman](brakeman.url).  Brakeman is a powerful static code analysis tool and can often detect potentially vulnerable areas of code. Amongst other warnings, Brakeman produced the following warning related to Command Injection in the `abstract_adapter.rb` file.  At first glance this looks like a vulnerable implementation of the `IO.popen` method.

```shell
Confidence: Medium
Category: Command Injection
Check: Execute
Message: Possible command injection
Code: IO.popen("#{cmd} 2>>#{shell_quote(stderr_log_file)}", "r+")
File: lib/redmine/scm/adapters/abstract_adapter.rb
Line: 247
```

## AbstractAdapter

Within the `AbstractAdapter` it looks like the vulnerable method is inside the following method in `AbstractAdapter` in the `shellout` [method](https://github.com/redmine/redmine/blob/master/lib/redmine/scm/adapters/abstract_adapter.rb#L247):


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

It looks like this method simply receives the `cmd` variable, and passes it to the `IO.popen`.  So far, it seems that this method is vulnerable.  The `AbstractAdapter` is a superclass for various adapters that Redmine uses to process SCM commands to various VCS systems.  We will need to look at some of the subclasses to find where `shellout` is called.

## GitAdapter

Within the `GitAdapter` class, there are only two calls to `shellout`.  One of which occurs in the `git_cmd` helper method:

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

There is a lot going on here, but it seems that the `args` argument is appended to the `full_args` array.  The `full_args` array is mapped over and the `shell_quote` method is used against each element, and they are joined by a space.

## Utils

Looking further through the codebase, it appears that the `shell_quote` method is defined in the `Utils` [module](https://github.com/redmine/redmine/blob/master/lib/redmine/utils.rb)

```Ruby
  def shell_quote(str)
    if Redmine::Platform.mswin?
      '"' + str.gsub(/"/, '\\"') + '"'
    else
      "'" + str.gsub(/'/, "'\"'\"'") + "'"
    end
  end
```

This method receives a string and, depending on the OS, wraps the quote character in single quotes.  It then wraps the final string in quotes - double quotes in Windows, single quotes in other OSes.  The quotes here are important.

It seems that this particular area of the code, even if we can control the input, will not result in a malicious command being executed.

There is a very subtle caveat to this protection.

It is important to note that they wrapped the bash command in *single quotes*.  This allows an attacker to interpolate values.  For example:
```shell
echo 'git branch '"$BASH"''
```
will produce the command
```
git branch /bin/bash
```
