<?php
// Table name of app specific/custom user data. (string)
define('AUTH3_USERDATATABLE', 'users');

// Throttling. (bool)
define('AUTH3_THROTTLING', false);

// Invite code for registration. If empty string, captcha used. (string)
define('AUTH3_INVITECODE', '');

// Email verification email send from. (string)
define('AUTH3_EMAILFROM', '');

// Store email in DB and send verification email during registration
define('AUTH3_EMAIL_REQUIRED', true);