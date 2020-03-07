<?php declare(strict_types = 1);

namespace resist\Auth3;

use Base;
use DB\SQL;
use DB\SQL\Mapper;
use Exception;

class UserMap extends Mapper
{
    public function __construct(Base $f3, SQL $db)
    {
        parent::__construct($db, AUTH3_USERDATATABLE);

        $this->load(['uid = :uid', ':uid' => $f3->get('uid')]);
        if ($this->dry()) {
            throw new Exception('Invalid user ID for user.');
        }
    }
}