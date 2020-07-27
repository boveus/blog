---
title: "Secure Authentication Mechanisms"
date: 2020-07-26
slug: "secure-authentication-mechanisms"
description: "Protecting against Command Injection - a practical example of secure coding in Ruby on Rails from the Redmine project."
keywords: ['authentication', 'security', 'secure coding', 'laravel', '2FA']
draft: true
tags: []
math: false
toc: false
---

In this post I will walk through a few areas of the [Cachet](https://cachethq.io/) application and analyze how the authors handled various authentication mechanisms in it.  I will cover some of the best practices related to storing user passwords and other secure tokens as well as how the authors implemented two factor authentication.  This post will touch on aspects of `Broken Authentication` and `Sensitive Data Exposure` #2 and #3 of the OWASP top 10 vulnerabilities respectively.

## Broken authentication

OWASP describes broken authentication as the following:

> Application functions related to authentication and session management are often implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users’ identities temporarily or permanently.

Below are some highlights from OWASP's [recommendations](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication) to protect against Broken authentication:

* Where possible, implement multi-factor authentication to prevent automated, credential stuffing, brute force, and stolen credential re-use attacks.
* Ensure registration, credential recovery, and API pathways are hardened against account enumeration attacks by using the same messages for all outcomes.
* Limit or increasingly delay failed login attempts. Log all failures and alert administrators when credential stuffing, brute force, or other attacks are detected.
* Use a server-side, secure, built-in session manager that generates a new random session ID with high entropy after login. Session IDs should not be in the URL, be securely stored and invalidated after logout, idle, and absolute timeouts.

## Sensitive Data exposure

OWASP says the following about Sensitive Data Exposure:

> Sensitive Data Exposure. Many web applications and APIs do not properly protect sensitive data, such as financial, healthcare, and PII. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes. Sensitive data may be compromised without extra protection, such as encryption at rest or in transit, and requires special precautions when exchanged with the browser.

And to following [recommendations](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure) protect against Sensitive Data Exposure:

* Ensure up-to-date and strong standard algorithms, protocols, and keys are in place; use proper key management.
* Disable caching for response that contain sensitive data.
* Store passwords using strong adaptive and salted hashing functions with a work factor (delay factor), such as Argon2, scrypt, bcrypt or PBKDF2.
