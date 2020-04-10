<?php declare(strict_types=1);

namespace resist\Auth3;

use Base;
use DB\SQL;
use Delight\Auth\AmbiguousUsernameException;
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

    private const AUTH3L10N_SIGNUPSUCCESS = 'Sikeres regisztráció. Email megerősítés szükséges!';
    private const AUTH3L10N_LOGINSUCCESS = 'Sikeres bejelentkezés.';
    private const AUTH3L10N_LOGOUTSUCCESS = 'Sikeres kijelentkezés.';

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
            $query = 'SELECT * FROM '.AUTH3_USERDATATABLE.' WHERE `uid` = :uid LIMIT 1';
            $userData = $this->db->exec($query, [':uid' => $uid]);
            if (!empty($userData)) {
                return $userData[0];
            }
        }
        return [];
    }

    private function sendVerificationEmail(string $selector, string $token, string $emailTo): void
    {
        $emailSubject = '['.$_SERVER['HTTP_HOST'].'] [Email megerősítés] ';
        $link = $this->f3->home.'signup/verify/'.$selector.'/'.$token;
        $emailMessage = 'Email megerősítése: <a href="'.$link.'">'.$link.'</a>';
        $emailHeaders = 'From: '.AUTH3_EMAILFROM."\r\n".
            'Reply-To: '.AUTH3_EMAILFROM."\r\n" .
            'Content-type: text/html;charset=UTF-8'."\r\n" .
            'X-Mailer: PHP/'.phpversion();
        mail($emailTo, $emailSubject, $emailMessage, $emailHeaders);
        $this->logger->create('info', 'auth3 signup - email sent', [$emailSubject, $emailTo]);
    }

    public function signup(string $email, string $password, string $username): void
    {
        try {
            $userId = $this->auth->registerWithUniqueUsername($email, $password, $username, function ($selector, $token) use ($email) {
                $this->sendVerificationEmail($selector, $token, $email);
            });

            $this->auth->admin()->addRoleForUserById($userId, Role::SUBSCRIBER);

            // Create empty row in user-data table
            $query = 'INSERT INTO '.AUTH3_USERDATATABLE.' (`uid`) VALUES (:uid)';
            $this->db->exec($query, [':uid' => $userId]);

            $this->flash->addMessage(self::AUTH3L10N_SIGNUPSUCCESS, 'success');
            $this->logger->create('success', 'auth3 signup', [$email, $username]);
            $this->f3->reroute('@login');
        } catch (InvalidEmailException $e) {
            $this->flash->addMessage('Invalid email address', 'danger');
            $this->logger->create('warning', 'auth3 signup - invalid email', [$email]);
            $this->f3->reroute('@signup');
        } catch (InvalidPasswordException $e) {
            $this->flash->addMessage('Invalid password', 'danger');
            $this->logger->create('warning', 'auth3 signup - invalid password', [$password]);
            $this->f3->reroute('@signup');
        } catch (UserAlreadyExistsException $e) {
            $this->flash->addMessage('Már van ilyen (email vagy név) felhasználó a rendszerben.', 'danger');
            $this->logger->create('warning', 'auth3 signup - duplicated user', [$email, $username]);
            $this->f3->reroute('@signup');
        } catch (TooManyRequestsException $e) {
            $this->flash->addMessage('Too many requests', 'danger');
            $this->logger->create('warning', 'auth3 signup - too many request', [$email, $username]);
            $this->f3->reroute('@signup');
        }
    }

    public function signupWithoutEmail(string $password, string $username): void
    {
        try {
            $userId = $this->auth->registerWithUniqueUsername(\H3::gen(20).'@localhost', $password, $username);

            $this->auth->admin()->addRoleForUserById($userId, Role::SUBSCRIBER);

            // Create empty row in user-data table
            $query = 'INSERT INTO '.AUTH3_USERDATATABLE.' (`uid`) VALUES (:uid)';
            $this->db->exec($query, [':uid' => $userId]);

            $this->flash->addMessage(self::AUTH3L10N_SIGNUPSUCCESS, 'success');
            $this->logger->create('success', 'auth3 signup', [$username]);
            $this->f3->reroute('@login');
        } catch (InvalidEmailException $e) {
            $this->flash->addMessage('Invalid email address', 'danger');
            $this->logger->create('warning', 'auth3 signup - invalid email', [$userId, $username]);
            $this->f3->reroute('@signup');
        } catch (InvalidPasswordException $e) {
            $this->flash->addMessage('Invalid password', 'danger');
            $this->logger->create('warning', 'auth3 signup - invalid password', [$password]);
            $this->f3->reroute('@signup');
        } catch (UserAlreadyExistsException $e) {
            $this->flash->addMessage('Már van ilyen (email vagy név) felhasználó a rendszerben.', 'danger');
            $this->logger->create('warning', 'auth3 signup - duplicated user', [$username]);
            $this->f3->reroute('@signup');
        } catch (TooManyRequestsException $e) {
            $this->flash->addMessage('Too many requests', 'danger');
            $this->logger->create('warning', 'auth3 signup - too many request', [$username]);
            $this->f3->reroute('@signup');
        } catch (UnknownIdException $e) {
            $this->flash->addMessage('Unknown Id', 'danger');
            $this->logger->create('warning', 'auth3 signup - Unknown Id', [$userId]);
            $this->f3->reroute('@signup');
        }
    }

    public function loginWithUsername(string $username, string $password, ?int $duration): void
    {
        try {
            $this->auth->loginWithUsername($username, $password, $duration);
            $this->flash->addMessage(self::AUTH3L10N_LOGINSUCCESS, 'success');
            $this->f3->reroute('/');
        } catch (InvalidPasswordException $e) {
            $this->flash->addMessage('Wrong password', 'danger');
            $this->logger->create('warning', 'auth3 login - invalid email', [$username]);
            $this->f3->reroute('@login');
        } catch (EmailNotVerifiedException $e) {
            $this->flash->addMessage('Email not verified', 'danger');
            $this->logger->create('warning', 'auth3 login - unverified email', [$username]);
            $this->f3->reroute('@login');
        } catch (TooManyRequestsException $e) {
            $this->flash->addMessage('Too many requests', 'danger');
            $this->logger->create('warning', 'auth3 login - too many requests', [$username]);
            $this->f3->reroute('@login');
        } catch (UnknownUsernameException $e) {
            $this->flash->addMessage('Invalid username', 'danger');
            $this->logger->create('warning', 'auth3 login - unknown username', [$username]);
            $this->f3->reroute('@login');
        } catch (AmbiguousUsernameException $e) {
            $this->flash->addMessage('Invalid username', 'danger');
            $this->logger->create('warning', 'auth3 login - invalid username', [$username]);
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

        $this->flash->addMessage(self::AUTH3L10N_LOGOUTSUCCESS, 'success');
        $this->f3->reroute('/');
    }

    public function verify(string $selector, string $token): void
    {
        try {
            $email = $this->auth->confirmEmailAndSignIn($selector, $token);

            $this->flash->addMessage($email[1].' cím megerősítveés automatikusan beléptetve.', 'success');
            $this->logger->create('success', 'auth3 verify', [$email[1]]);
            $this->f3->reroute('@login');
        }
        catch (InvalidSelectorTokenPairException $e) {
            $this->flash->addMessage('Invalid token.', 'danger');
            $this->logger->create('warning', 'auth3 verify - invalid token');
            $this->f3->reroute('@login');
        }
        catch (TokenExpiredException $e) {
            $this->flash->addMessage('Token expired.', 'danger');
            $this->logger->create('warning', 'auth3 verify - token expired',);
            $this->f3->reroute('@login');
        }
        catch (UserAlreadyExistsException $e) {
            $this->flash->addMessage('Email address already exists.', 'danger');
            $this->logger->create('warning', 'auth3 verify - already verified',);
            $this->f3->reroute('@login');
        }
        catch (TooManyRequestsException $e) {
            $this->flash->addMessage('Too many requests.', 'dager');
            $this->logger->create('warning', 'auth3 verify - too many requests',);
            $this->f3->reroute('@login');
        }
    }
}
