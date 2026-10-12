<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Schedule;

use Symfony\Component\Scheduler\RecurringMessage;
use Symfony\Component\Scheduler\Schedule;
use Symfony\Component\Scheduler\ScheduleProviderInterface;

/**
 * The daily check. Add message() to your own schedule instead if you'd rather
 * have one scheduler worker.
 */
final class SecurityAlertsSchedule implements ScheduleProviderInterface
{
    public function __construct(private readonly string $time = '07:00', private readonly ?string $timezone = null)
    {
    }

    public static function message(string $time = '07:00', ?string $timezone = null): RecurringMessage
    {
        $zone = $timezone !== null ? new \DateTimeZone($timezone) : null;
        $from = new \DateTimeImmutable('today '.$time, $zone);

        return RecurringMessage::every('1 day', new CheckMessage(), $from);
    }

    public function getSchedule(): Schedule
    {
        return (new Schedule())->add(self::message($this->time, $this->timezone));
    }
}
