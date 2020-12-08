<?php declare(strict_types=1);

namespace resist\Auth3;

use Base;
use Flash;
use GUMP;
use \resist\H3\Logger;

class Auth3Controller
{
    private Base $f3;
    private Auth3 $auth3;
    private Flash $flash;
    private GUMP $gump;
    private Logger $logger;

    public function __construct(Base $f3, Auth3 $auth3, Flash $flash, GUMP $gump, Logger $logger)
    {
        $this->f3 = $f3;
        $this->auth3 = $auth3;
        $this->flash = $flash;
        $this->gump = $gump;
        $this->logger = $logger;
    }

    public function signupControlling(): array
    {
        $_POST['codeconfirm'] = AUTH3_INVITECODE;

        if (isset($_SESSION['captcha']) && AUTH3_CAPTCHA === true) {
            $_POST['codeconfirm'] = $_SESSION['captcha'] .AUTH3_INVITECODE;
        }

        $emailRule = 'required|valid_email';
        if (AUTH3_EMAIL_REQUIRED === false) {
            $emailRule = 'valid_email';
        }

        $this->gump->validation_rules([
            'username' => 'required',
            'password' => 'required|min_len,1',
            'passwordconfirm' => 'required|min_len,1|equalsfield,password',
            'code' => 'required|equalsfield,codeconfirm',
            'email' => $emailRule,
        ]);

        $this->gump->filter_rules([
            'username' => 'trim',
            'email' => 'trim|sanitize_email',
        ]);

        $validPost = $this->gump->run($_POST);

        if ($validPost === false) {
            $this->flash->addMessage($this->gump->get_readable_errors(true), 'danger');
            $this->logger->create('warning', 'auth3 signup - controller validation', [$this->gump->get_errors_array(), $_POST]);
            return [];
        }

        $this->f3->scrub($_POST['username']);

        if (AUTH3_EMAIL_REQUIRED === false) {
            return $this->auth3->signupWithoutEmail($_POST['password'], $_POST['username']);
        }

        return $this->auth3->signup($_POST['email'], $_POST['password'], $_POST['username']);
    }

    /** @used */
    public function signupController(Base $f3): void
    {
        if (empty($this->signupControlling())) {
            $f3->reroute('@signup');
        }
        $f3->reroute('@login');
    }

    /** @used */
    public function loginController(Base $f3): void
    {
        $this->gump->validation_rules([
            'username' => 'required',
            'password' => 'required'
        ]);

        $this->gump->filter_rules([
            'username' => 'trim'
        ]);

        $validPost = $this->gump->run($_POST);

        if ($validPost === false) {
            $this->flash->addMessage($this->gump->get_readable_errors(true), 'danger');
            $this->logger->create('warning', 'Auth3Controller::loginController - Failed validation', [$this->gump->get_errors_array(), $_POST]);
            $f3->reroute('@login');
        }

        $duration = null;
        if (isset($_POST['remember']) && $_POST['remember'] === '1') {
            $duration = 60*60*24*30;
        }

        setcookie( session_name(), '', time()-3600, '/');

        $this->auth3->loginWithUsername($_POST['username'], $_POST['password'], $duration);
    }

    /** @used */
    public function logoutController(Base $f3): void
    {
        $this->auth3->logout();
    }

    /** @used */
    public function verificationController(Base $f3): void
    {
        $this->auth3->verify($f3->get('PARAMS.selector'), $f3->get('PARAMS.token'));
    }
}