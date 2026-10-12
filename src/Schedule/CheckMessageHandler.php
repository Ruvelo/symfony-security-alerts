<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Schedule;

use Ruvelo\SecurityAlertsBundle\Check\Checker;

final class CheckMessageHandler
{
    public function __construct(private readonly Checker $checker)
    {
    }

    public function __invoke(CheckMessage $message): void
    {
        $this->checker->check();
    }
}
