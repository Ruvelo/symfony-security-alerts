<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Check;

use Ruvelo\SecurityAdvisories\Changes;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Report;

final readonly class CheckResult
{
    /**
     * @param list<Finding> $announced Findings the alert was about
     * @param int           $held      How many findings were left unrecorded because the alert failed; the next check retries them
     */
    public function __construct(
        public Report $report,
        public Changes $changes,
        public Delivery $delivery = Delivery::None,
        public array $announced = [],
        public int $held = 0,
        public ?string $error = null,
    ) {
    }
}
