<?php declare(strict_types=1);

namespace resist\Auth3;

use \Base;
use \Image;

class CaptchaController
{
    public const SESSIONNAME = 'captcha';
    private const FONT = 'captcha.ttf';
    private const FONTSIZE = 16;
    private const LENGTH = 5;

    public Base $f3;
    private Image $image;

    public function __construct(Base $f3, Image $image)
    {
        $this->f3 = $f3;
        $this->image = $image;

        $this->spreadFont();
    }

    public function renderCaptcha(): void
    {
        $this->image->captcha(self::FONT, self::FONTSIZE, self::LENGTH, 'SESSION.'.self::SESSIONNAME);
        $this->image->render();
    }

    // API END ////

    private function spreadFont(): void
    {
        $this->f3->set('UI', $this->f3->get('UI').';vendor/resist/Auth3/font/');
    }
}
