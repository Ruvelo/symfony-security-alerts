<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Command;

use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * Advisory titles come from the internet: they must not be read as console tags.
 *
 * @internal
 */
final class OutputFormatterEscape
{
    public static function escape(string $text): string
    {
        return OutputFormatter::escape($text);
    }
}
