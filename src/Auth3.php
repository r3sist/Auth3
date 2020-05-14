<?php declare(strict_types=1);

namespace resist\Auth3;

use Base;
use DB\SQL;
use Delight\Auth\AmbiguousUsernameException;
use Delight\Auth\AttemptCancelledException;
use Delight\Auth\AuthError;
use Delight\Auth\DuplicateUsernameException;
use Delight\Auth\EmailNotVerifiedException;
use Delight\Auth\InvalidPasswordException;
use Delight\Auth\InvalidSelectorTokenPairException;
use Delight\Auth\Role;
use Delight\Auth\TokenExpiredException;
use Delight\Auth\TooManyRequestsException;
use Delight\Auth\UnknownIdException;
use Delight\Auth\UnknownUsernameException;
use Delight\Auth\UserAlreadyExistsException;
use Flash;
use GUMP;
use Delight\Auth\Auth;
use Delight\Auth\InvalidEmailException;
use H3;
use resist\H3\Logger;

class Auth3
{
    private const TABLEPREFIX = 'auth3_';

    private Base $f3;
    private SQL $db;
    private Flash $flash;
    private GUMP $gump;
    private Logger $logger;
    private Auth $auth;

    private const AUTH3L10N_SUCCESS_SIGNUP = 'Sikeres regisztráció. Email megerősítés szükséges!';
    private const AUTH3L10N_SUCCESS_SIGNUPALT = 'Sikeres regisztráció.';
    private const AUTH3L10N_SUCCESS_LOGOUT = 'Sikeres kijelentkezés.';
    private const AUTH3L10N_SUCCESS_VERIFIED = ' email cím megerősítve és a hozzá tartozó fiókba automatikusan beléptetve.';

    private const AUTH3L10N_ERROR_DUPLICATEDUSERNAME = 'Már foglalt a megadott felhasználó név a rendszerben.';
    private const AUTH3L10N_ERROR_INVALIDEMAIL = 'Hibás formátumú email cím lett megadva.';
    private const AUTH3L10N_ERROR_INVALIDPASSWORD = 'Hibás formátumú jelszó lett megadva.';
    private const AUTH3L10N_ERROR_INVALIDUSER = 'Már van ilyen felhasználó (email vagy név) a rendszerben.';
    private const AUTH3L10N_ERROR_TOOMANYREQUEST = 'Túl sok HTTP kérés történt egyszerre.';
    private const AUTH3L10N_ERROR = 'Autentikációs hiba.';
    private const AUTH3L10N_ERROR_UNKNOWNID = 'Hibás felhasználó azonosító.';
    private const AUTH3L10N_ERROR_WRONGPASSWORD = 'Hibás jelszó lett megadva.';
    private const AUTH3L10N_ERROR_WRONGUSERNAME = 'A megadott felhasználói névvel nincs fiók a rendszerben.';
    private const AUTH3L10N_ERROR_EMAILNOTVERIFIED = 'A fiókhoz társított email cím még nem lett megerősítve.';
    private const AUTH3L10N_ERROR_INVALIDVERIFICATION = 'Hibás email megerősítés. (Hibás azonosítók megadása vagy lejárt kulcsok.)';
    private const AUTH3L10N_ERROR_ALREADYVERIFIED = 'Az email cím már meg lett erősítve.';

    private const AUTH3L10N_EMAIL_SUBJECT = '[Email megerősítés]';
    private const AUTH3L10N_EMAIL_BODY0 = 'Email megeríősítése: ';

    public function __construct(Base $f3, SQL $db, GUMP $gump, Logger $logger)
    {
        $this->f3 = $f3;
        $this->db = $db;
        $this->flash = Flash::instance();
        $this->gump = $gump;
        $this->logger = $logger;
        $this->auth = new Auth($db->pdo(), null, self::TABLEPREFIX, AUTH3_THROTTLING);

        $uid = $this->auth->getUserId();
        $this->spreadData($uid);
        $this->spreadRoutes();
    }

    private function spreadRoutes(): void
    {
        $this->f3->route('POST /login', '\resist\Auth3\Auth3Controller->loginController');
        $this->f3->route('POST /signup', '\resist\Auth3\Auth3Controller->signupController');
        $this->f3->route('GET @logout: /logout', '\resist\Auth3\Auth3Controller->logoutController');
        $this->f3->route('GET @captcha: /captcha', '\resist\Auth3\Auth3Controller->renderCaptcha');
        $this->f3->route('GET /signup/verify/@selector/@token', '\resist\Auth3\Auth3Controller->verificationController');
    }

    private function spreadData(?int $uid): void
    {
        $this->f3->set('uid', 0);
        $this->f3->set('uname', '');
        $this->f3->set('udata', []);
        $this->f3->set('auth', $this->auth);
        $this->f3->set('mobile', \Audit::instance()->ismobile());
        if ($uid !== null) {
            $this->f3->set('uid', $uid);
            $this->f3->set('uname', $this->auth->getUsername());
            $this->f3->set('udata', $this->getUserCustomData($uid));
        }
    }

    private function getUserCustomData(int $uid): array
    {
        if (AUTH3_USERDATATABLE !== '') {
            $query = 'SELECT * FROM '.AUTH3_USERDATATABLE.' WHERE `uid` = :uid LIMIT 1 -- Auth3 getUserCustomData';
            $userData = $this->db->exec($query, [':uid' => $uid]);
            if (!empty($userData)) {
                return $userData[0];
            }
        }
        return [];
    }

    private function sendVerificationEmail(string $selector, string $token, string $emailTo): void
    {
        $emailSubject = '['.$_SERVER['HTTP_HOST'].'] '.self::AUTH3L10N_EMAIL_SUBJECT;
        $link = $this->f3->home.'signup/verify/'.$selector.'/'.$token;
        $emailMessage = self::AUTH3L10N_EMAIL_BODY0.'<a href="'.$link.'">'.$link.'</a>';
        $emailHeaders = 'From: '.AUTH3_EMAILFROM."\r\n".
            'Reply-To: '.AUTH3_EMAILFROM."\r\n" .
            'Content-type: text/html;charset=UTF-8'."\r\n" .
            'X-Mailer: PHP/'.phpversion();
        mail($emailTo, $emailSubject, $emailMessage, $emailHeaders);
        $this->logger->create('info', 'Auth3::sendVerificationEmail - Email sent', [$emailSubject, $emailTo]);
    }

    public function signup(string $email, string $password, string $username): void
    {
        $userId = 0;
        try {
            $userId = $this->auth->registerWithUniqueUsername($email, $password, $username, function ($selector, $token) use ($email) {
                $this->sendVerificationEmail($selector, $token, $email);
            });

            $this->auth->admin()->addRoleForUserById($userId, Role::SUBSCRIBER);

            // Create empty row in user-data table
            $query = 'INSERT INTO '.AUTH3_USERDATATABLE.' (`uid`) VALUES (:uid)';
            $this->db->exec($query, [':uid' => $userId]);

            $this->flash->addMessage(self::AUTH3L10N_SUCCESS_SIGNUP, 'success');
            $this->logger->create('success', 'Auth3::signup', [$email, $username]);
            $this->f3->reroute('@login');
        } catch (InvalidEmailException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_INVALIDEMAIL, 'danger');
            $this->logger->create('warning', 'Auth3::signup - Invalid email', [$email]);
            $this->f3->reroute('@signup');
        } catch (InvalidPasswordException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_INVALIDPASSWORD, 'danger');
            $this->logger->create('warning', 'Auth3::ignup - Invalid password', [$password]);
            $this->f3->reroute('@signup');
        } catch (UserAlreadyExistsException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_INVALIDUSER, 'danger');
            $this->logger->create('warning', 'Auth3::signup - Duplicated user', [$email, $username]);
            $this->f3->reroute('@signup');
        } catch (TooManyRequestsException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_TOOMANYREQUEST, 'danger');
            $this->logger->create('warning', 'Auth3::signup - Too many request', [$email, $username]);
            $this->f3->reroute('@signup');
        } catch (AuthError $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR, 'danger');
            $this->logger->create('danger', 'Auth3::signup - Auth general error', [$email, $username]);
            $this->f3->reroute('@signup');
        } catch (DuplicateUsernameException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_DUPLICATEDUSERNAME, 'danger');
            $this->logger->create('warning', 'Auth3::signup - Duplicated username', [$username]);
            $this->f3->reroute('@signup');
        } catch (UnknownIdException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_UNKNOWNID, 'danger');
            $this->logger->create('warning', 'Auth3::signup - Unknown user ID', [$userId]);
            $this->f3->reroute('@signup');
        }
    }

    public function signupWithoutEmail(string $password, string $username): void
    {
        $userId = 0;
        try {
            $userId = $this->auth->registerWithUniqueUsername(H3::gen(40).'@sorfi.org', $password, $username);

            $this->auth->admin()->addRoleForUserById($userId, Role::SUBSCRIBER);

            // Create empty row in user-data table
            $query = 'INSERT INTO '.AUTH3_USERDATATABLE.' (`uid`) VALUES (:uid) -- Auth3 signupWithoutEmail';
            $this->db->exec($query, [':uid' => $userId]);

            $this->flash->addMessage(self::AUTH3L10N_SUCCESS_SIGNUPALT, 'success');
            $this->logger->create('success', 'Auth3::signupWithoutEmail', [$username]);
            $this->f3->reroute('@login');
        } catch (InvalidEmailException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_INVALIDEMAIL, 'danger');
            $this->logger->create('warning', 'Auth3::signupWithoutEmail - Invalid email', [$userId, $username]);
            $this->f3->reroute('@signup');
        } catch (InvalidPasswordException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_INVALIDPASSWORD, 'danger');
            $this->logger->create('warning', 'Auth3::signupWithoutEmail - Invalid password', [$password]);
            $this->f3->reroute('@signup');
        } catch (UserAlreadyExistsException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_INVALIDUSER, 'danger');
            $this->logger->create('warning', 'Auth3::signupWithoutEmail - Duplicated user', [$username]);
            $this->f3->reroute('@signup');
        } catch (TooManyRequestsException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_TOOMANYREQUEST, 'danger');
            $this->logger->create('warning', 'Auth3::signupWithoutEmail - Too many request', [$username]);
            $this->f3->reroute('@signup');
        } catch (UnknownIdException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_UNKNOWNID, 'danger');
            $this->logger->create('warning', 'Auth3::signupWithoutEmail - Unknown user ID', [$userId]);
            $this->f3->reroute('@signup');
        } catch (AuthError $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR, 'danger');
            $this->logger->create('danger', 'Auth3::signupWithoutEmail - Auth general error', [$username]);
            $this->f3->reroute('@signup');
        } catch (DuplicateUsernameException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_DUPLICATEDUSERNAME, 'danger');
            $this->logger->create('warning', 'Auth3::signupWithoutEmail - Duplicated username', [$username]);
            $this->f3->reroute('@signup');
        }
    }

    public function loginWithUsername(string $username, string $password, ?int $duration): void
    {
        try {
            $this->auth->loginWithUsername($username, $password, $duration);
            $this->f3->reroute('/');
        } catch (InvalidPasswordException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_WRONGPASSWORD, 'danger');
            $this->logger->create('warning', 'Auth3::loginWithUsername - Wrong password', [$username]);
            $this->f3->reroute('@login');
        } catch (EmailNotVerifiedException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_EMAILNOTVERIFIED, 'danger');
            $this->logger->create('warning', 'Auth3::loginWithUsername - Unverified email', [$username]);
            $this->f3->reroute('@login');
        } catch (TooManyRequestsException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_TOOMANYREQUEST, 'danger');
            $this->logger->create('warning', 'Auth3::loginWithUsername - Too many requests', [$username]);
            $this->f3->reroute('@login');
        } catch (UnknownUsernameException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_WRONGUSERNAME, 'danger');
            $this->logger->create('warning', 'Auth3::loginWithUsername - Unknown username', [$username]);
            $this->f3->reroute('@login');
        } catch (AmbiguousUsernameException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_WRONGUSERNAME, 'danger');
            $this->logger->create('danger', 'Auth3::loginWithUsername - Invalid username', [$username]);
            $this->f3->reroute('@login');
        } catch (AttemptCancelledException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR, 'danger');
            $this->logger->create('warning', 'Auth3::loginWithUsername - Cancelled attempt', [$username]);
            $this->f3->reroute('@login');
        } catch (AuthError $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR, 'danger');
            $this->logger->create('danger', 'Auth3::loginWithUsername - Auth general error', [$username]);
            $this->f3->reroute('@login');
        }
    }

    public function logout(): void
    {
        try {
            $this->auth->logOutEverywhere();
            $this->auth->destroySession();
        } catch (\Throwable $e) {

        }

        $this->flash->addMessage(self::AUTH3L10N_SUCCESS_LOGOUT, 'success');
        $this->f3->reroute('/');
    }

    public function verify(string $selector, string $token): void
    {
        try {
            $email = $this->auth->confirmEmailAndSignIn($selector, $token);

            $this->flash->addMessage($email[1].self::AUTH3L10N_SUCCESS_VERIFIED, 'success');
            $this->logger->create('success', 'Auth3::verify', [$email[1]]);
            $this->f3->reroute('@login');
        }
        catch (InvalidSelectorTokenPairException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_INVALIDVERIFICATION, 'danger');
            $this->logger->create('danger', 'Auth3::verify - Invalid selector-token pair', '');
            $this->f3->reroute('@login');
        }
        catch (TokenExpiredException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_INVALIDVERIFICATION, 'danger');
            $this->logger->create('danger', 'Auth3::verify - Expired token', '');
            $this->f3->reroute('@login');
        }
        catch (UserAlreadyExistsException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_ALREADYVERIFIED, 'danger');
            $this->logger->create('warning', 'Auth3::verify - Already verified', '');
            $this->f3->reroute('@login');
        }
        catch (TooManyRequestsException $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR_TOOMANYREQUEST, 'dager');
            $this->logger->create('warning', 'Auth3::verify - Too many requests', '');
            $this->f3->reroute('@login');
        } catch (AuthError $e) {
            $this->flash->addMessage(self::AUTH3L10N_ERROR, 'danger');
            $this->logger->create('danger', 'Auth3::verify - Auth general error', '');
            $this->f3->reroute('@login');
        }
    }
}
