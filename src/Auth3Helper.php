<?php declare(strict_types=1);

namespace resist\Auth3;

use Delight\Auth\Auth;

class Auth3Helper
{
    /**
     * @param bool|string|array $roles
     * @param int|string $redirect
     */
    public static function access($roles, $redirect = 403, string $message = 'Nincs felhasználói jogosultságod az oldal megtekintéséhez.'): void
    {
        $f3 = \Base::instance();

        /** @var Auth $auth */
        $auth = $f3->get('auth');

        if (is_array($roles)) {
            array_map(static function ($role) {return constant("\Delight\Auth\Role::$role");}, $roles);
            $access = $auth->hasAnyRole(...$roles);
        } else if ($roles === true) {
            $access = (bool)$f3->uid;
        } else if ($roles === false) {
            $access = !(bool)$f3->uid;
        } else {
            $access = $auth->hasRole(constant("\Delight\Auth\Role::$roles"));
        }

        if ($access !== true) {
            if (is_numeric($redirect)) {
                $f3->error($redirect);
            } else {
                \Flash::instance()->addMessage($message, 'danger');
                $f3->reroute($redirect);
            }
        }
    }

    public static function isAdmin(): bool
    {
        return \Base::instance()->get('auth')->hasRole(\Delight\Auth\Role::ADMIN);
    }

    // TODO touch
}