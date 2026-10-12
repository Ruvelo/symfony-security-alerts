<?php

declare(strict_types=1);

use Ruvelo\SecurityAlertsBundle\Tests\Support\TestKernel;
use Symfony\Bundle\FrameworkBundle\Console\Application;

require __DIR__.'/../vendor/autoload.php';

return new Application(new TestKernel());
