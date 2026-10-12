<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Check;

enum Delivery: string
{
    /** Nothing new to say */
    case None = 'none';
    case Sent = 'sent';
    /** There was news but no recipient or channel to tell */
    case NotConfigured = 'not_configured';
    case Failed = 'failed';
}
