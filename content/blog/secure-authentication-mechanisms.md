---
title: "Secure Authentication Mechanisms"
date: 2020-08-09
slug: "secure-authentication-mechanisms"
description: "Protecting against Command Injection - a practical example of secure coding in Ruby on Rails from the Redmine project."
keywords: ['authentication', 'security', 'secure coding', 'laravel', '2FA']
draft: false
tags: []
math: false
toc: false
---

In this post I will walk through a few areas of the [Cachet](https://cachethq.io/) application and analyze how the authors handled various authentication mechanisms and stored sensitive data.  I will cover some of the best practices related to storing user passwords and other secure tokens as well as how the authors implemented two factor authentication.  I will go into detail about some of the vulnerabilities in 2FA and how to harden a 2FA implementation.  This post will touch on aspects of `Broken Authentication` and `Sensitive Data Exposure` #2 and #3 of the OWASP top 10 vulnerabilities respectively.

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

## Analysis of Cachet

Cachet is a popular open-source status monitoring tool written in PHP using the Laravel framework.  It provides an organization with a simple interface to manage a status page, report incidents, and view metrics about outages and past incidents.

One of the features that they [advertise](https://cachethq.io/) is Two-factor authentication using the Google Authenticator app.  

## The User model in Cachet

Since I was focusing on authentication and sensitive information in this analysis, the first area of the code base that seemed interesting is the `user` model.  Looking at the migrations, the user model contains the following attributes:

```php
     $table->increments('id');
     $table->string('username');
     $table->string('password');
     $table->rememberToken();
     $table->string('email');
     $table->string('api_key');
     $table->boolean('active')->default(1);
     $table->tinyInteger('level')->default(2);
     $table->timestamps();

     $table->index('remember_token');
     $table->index('active');
     $table->unique('username');
     $table->unique('api_key');
     $table->unique('email');
     $table->string('google_2fa_secret')->nullable()->after('remember_token');
```

Some of the potentially sensitive information here seem to be the `password`, `api_key`, and `google_2fa_secret`

### The password field

When a user configures a password, the `User` object calls the following method:
```php
# User.php
...
public function setPasswordAttribute($password)
{
    $this->attributes['password'] = Hash::make($password);

    return $this;
}
...
```

This uses the password hashing mechanism that is [built into Laravel](https://laravel.com/docs/7.x/hashing) which uses the Bcrypt driver.  This appears to be a good choice as it will hash the password with a salt before persisting it to the database.  In general, it is a good choice to rely on widely used third party applications for hashing mechanisms.

## The API key field

When a user creates an account or manually refreshes their API key through the admin interface, a new API key is generated for them using the following method:

```php
# User.php
public static function generateApiKey()
{
    return Str::random(20);
}
```

This method seems suspect.  In many programming languages, `random` methods and functions are not cryptographically secure.  According to the Laravel [documentation](https://laravel.com/docs/7.x/helpers#method-str-random) this uses an implementation of the PHP [random_bytes](https://www.php.net/manual/en/function.random-bytes.php) function.  The PHP docs provide the following description of the `random_bytes` function:

```text
random_bytes ( int $length ) : string

Generates an arbitrary length string of cryptographic random bytes
that are suitable for cryptographic use,
such as when generating salts, keys or initialization vectors.

The sources of randomness used for this function are as follows:

   On Windows, » CryptGenRandom() will always be used. As of PHP 7.2.0,
   the » CNG-API will always be used instead.
   On Linux, the » getrandom(2) syscall will be used if available.
   On other platforms, /dev/urandom will be used.
   If none of the aforementioned sources are available,
   then an Exception will be thrown.
```

It appears that the `Str::random` function is cryptographically secure.

### Insecure Randomness

In the above example, the developers working on Cachet used a cryptographically secure random generation method.  A cryptographically secure random function's output needs to be either impossible or highly improbable to guess.  In other words, the values produced by a random function should not have a discernible pattern.  If a given pseudo-random output has a discernible pattern, then it is opens up an [Insecure Randomness](https://owasp.org/www-community/vulnerabilities/Insecure_Randomness) vulnerability.

An example of this type of vulnerability was discovered last month in [JHipster Kotlin](https://portswigger.net/daily-swig/app-generator-tool-jhipster-kotlin-fixes-fundamental-cryptographic-bug).

When generating secure tokens it is essential that the token generation mechanism uses a cryptographically secure pseudo random generation mechanism.

## Google 2FA secret

The Google 2FA secret it used through the Google Authenticator TOTP (Time-based One-time Password) application to handle 2 factor authentication within Cachet.

The token is created in the `UserController` when a user enables 2FA in the admin dashboard:
```php
        // Let's enable/disable auth
        if ($enable2FA && !Auth::user()->hasTwoFactor) {
            event(new UserEnabledTwoAuthEvent(Auth::user()));
            $google2fa = new Google2FA();
            $userData['google_2fa_secret'] = $google2fa->generateSecretKey();
        } elseif (!$enable2FA) {
            event(new UserDisabledTwoAuthEvent(Auth::user()));
            $userData['google_2fa_secret'] = '';
        }
```


The token is used in the `AuthController` to validate a given one-time password (the 6 digit number generate by the app).  This happens after a user with 2fa enabled successfully logs in with a correct username/password combination:

```php
public function postTwoFactor()
    {
        // Check that we have a session.
        if ($userId = Session::pull('2fa_id')) {
            $code = str_replace(' ', '', Binput::get('code'));

            // Maybe a temp login here.
            Auth::loginUsingId($userId);

            $user = Auth::user();

            $google2fa = new Google2FA();
            $valid = $google2fa->verifyKey($user->google_2fa_secret, $code);

            if ($valid) {
                event(new UserPassedTwoAuthEvent($user));

                event(new UserLoggedInEvent($user));

                return Redirect::intended('dashboard');
            } else {
                event(new UserFailedTwoAuthEvent($user));

                // Failed login, log back out.
                Auth::logout();

                return cachet_redirect('auth.login')->withError(trans('forms.login.invalid-token'));
            }
        }

        return cachet_redirect('auth.login')->withError(trans('forms.login.invalid-token'));
    }
```

This piece of code in particular seems to be where a 2FA library is used to validate a code using the `google_2fa_secret`:

```php
$google2fa = new Google2FA();
$valid = $google2fa->verifyKey($user->google_2fa_secret, $code);
```

The 2FA implementation is very straightforward.  The library handles the underlying time-based 2fa logic, but the pieces of information required for this to work are the user's email, their `shared_secret_key` (the google_2fa_secret) and the current (unix) time.

Pictured below is an example showing an example dashboard of this in practice:
![image](https://raw.githubusercontent.com/antonioribeiro/google2fa/8.x/docs/playground.jpg)


The TOTP 2FA [algorithm](https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm) uses the `shared_secret_key` and the current Unix Epoc Time, to produce a valid one time key.  This relies on the randomness of the current Unix Epoc Time in combination with the shared secret to authenticate a user. Because it uses Unix Epoc Time, there are [mostly](https://randomoracle.wordpress.com/2017/06/08/two-factor-authentication-a-matter-of-time/) not any issues comparing times across time zones.

### 2FA Secret Token - to encrypt or not to encrypt

The only secret component to the 2fa authentication scheme is the `shared_secret_key`.  This is shared between the server and the client (the user trying to log in) to create a token that is valid during a particular window of time (generally 30-60 seconds).

Interestingly, the `google_2fa_secret` is stored in plain text.  Initially this seemed very problematic, but after further discussion and research it seems that this is actually an acceptable practice.

While researching this question, I came across [this stackoverflow post](https://security.stackexchange.com/questions/42795/storing-seed-for-totp?rq=1) which provides two answers that offer reasons for encrypting the token and reasons for not encrypting the token.

#### Encrypting the token

The primary argument for encryption involves defense in depth and that the `shared_secret_key` should be treated like a password.

If an attacker compromises the application database and acquires a shared secret key they will be able to generate valid TOTP codes for users of that application.  This would be problematic if a user uses a weak password that an attacker can guess *and* the TOTP shared secret key is compromised.  

A secondary consideration is that any person with access to the production database can acquire a users secret key and generate valid one-time codes at will.  

The [RFC](https://tools.ietf.org/html/rfc4226#page-11) *recommends* encrypting the shared secret key:

```
   We also RECOMMEND storing the shared secrets securely, and more
   specifically encrypting the shared secrets when stored using tamper-
   resistant hardware encryption and exposing them only when required:
   for example, the shared secret is decrypted when needed to verify an
   HOTP value, and re-encrypted immediately to limit exposure in the RAM
   for a short period of time.  The data store holding the shared
   secrets MUST be in a secure area, to avoid as much as possible direct
   attack on the validation system and secrets database.
```

#### Against encrypting the token

The primary argument against encryption is that it requires additional  engineering effort.  Essentially, every single time a 2FA code is changed or used (every login with 2fa enabled) a decryption event would occur.  This would require additional engineering effort to manage the encrypted key.

The attack vector could be exploited in a *very* specific circumstance that 2FA is not intended to protect against.  If an attacker compromises the database they will likely have many other means to compromise user accounts or bypass authentication.  Depending on an organization's threat model it might not be worth the additional engineering effort to account for this scenario.

### What 2FA is and what it is not

2FA is not intended as a way of providing absolute protection against authentication bypass attacks.  It is intended to provide an additional layer of authentication to protect a user who uses a weak or compromised password.   

It is intended to make authentication bypass *more difficult*, but not *impossible*.  The recent attack against [twitter](https://threatpost.com/the-great-twitter-hack-what-we-know-what-we-dont/157538/), for example, relied on SIM-swapping to bypass a 2FA mechanism.  Just like a password, a 2FA code can be compromised.

### 2FA vulnerabilities and mitigation strategies

- The 2FA code can be acquired by either intercepting the request when the code is entered or observing a user input the code.  A good precaution against this type of attack is to verify the each key entered is newer than the previous key.  The PHP library's README [describes how to do this](https://github.com/antonioribeiro/google2fa#validation-window).

- An attacker could potentially [brute force](https://lukeplant.me.uk/blog/posts/6-digit-otp-for-two-factor-auth-is-brute-forceable-in-3-days/) a TOTP key if they have already acquired a user's password.  To mitigate against this attack vector, it would be a good idea to limit the number of incorrect 2FA attempts (similar to login attempts).

- 2FA can be phished just like a password can.  The short time window (30-60 seconds) make the code a bit more difficult to use, but this attack can be automated.  Unfortunately, there isn't a good mechanism to mitigate this attack other than educating users against phishing attacks.

- A [bigger key](https://github.com/antonioribeiro/google2fa#using-a-bigger-and-prefixing-the-secret-key) can help protect against the (highly improbable) situation of a key collision.

## Handling Authentication and storing sensitive data

- You should always hash and salt passwords. It is a good idea to rely on a well-supported third party library for this.

- When creating authentication tokens, you should use cryptographically secure pseudorandom functions.

- Allowing users to use 2FA is a great choice and by itself can help defend against authentication bypass attacks.  There are some additional steps that can be implemented to harden 2FA depending on your threat model.
