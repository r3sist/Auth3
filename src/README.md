# Auth3

**Wrapper of [Delight\Auth user authentication](https://github.com/delight-im/PHP-Auth) for Fat Free Framework powered apps.**

https://github.com/r3sist/Auth3

This repository is for personal use only. May contain hard coded Hungarian strings.

## Required constants

```php
// Table name of app specific/custom user data. (string)
define('AUTH3_USERDATATABLE', 'users');

// Throttling. (bool)
define('AUTH3_THROTTLING', false);

// Invite code for registration. If empty string, captcha used. (string)
define('AUTH3_INVITECODE', 'voyager3');

// Email verification email send from. (string)
define('AUTH3_EMAILFROM', 'vankos@resist.hu');
```

## Required F3 controller methods and named routes

Named routes are for redirects.

+ `GET @signup`
+ `GET @login`

## Defined *F3 Hive* variables

+ uid
+ uname
+ udata
+ auth
+ mobile

## Defined F3 controller methods

### POST signupController()

Email verification is disabled.

Method: `POST` only

Required parameters: 

+ `POST.username`: *required*; trimmed; cleaned silently
+ `POST.password`: *required|min_len,1*
+ `POST.passwordconfirm`: *required|min_len,1|equalsfield,password*
+ `POST.email`: *required|valid_email*; trimmed; sanitized

On error: rerouted to `@signup` with *flash message* contains GUMP readable errors

On success: rerouted to `@login` with *flash message*