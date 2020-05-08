<?php declare(strict_types = 1);

namespace resist\Auth3;

use DB\SQL;
use DB\SQL\Mapper;
use resist\Auth3\Exception\InvalidUserException;

class UserMap extends Mapper
{
    public function __construct(SQL $db)
    {
        parent::__construct($db, AUTH3_USERDATATABLE);
    }

    public function loadByUid(int $uid) :void
    {
        $this->load(['uid = :uid', ':uid' => $uid]);
        if ($this->dry()) {
            throw new InvalidUserException('Invalid user ID. (Error Auth3-00)');
        }
    }
}
