<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Notification;

interface Sender
{
    /**
     * @return bool False when there was nobody to tell (no recipients, no channels, no mailer)
     *
     * @throws \Throwable When delivery was attempted and failed
     */
    public function send(Alert $alert): bool;
}
