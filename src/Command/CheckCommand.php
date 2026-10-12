<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Command;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\SecurityAdvisoriesException;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAdvisories\Threshold;
use Ruvelo\SecurityAlertsBundle\Check\Checker;
use Ruvelo\SecurityAlertsBundle\Check\CheckResult;
use Ruvelo\SecurityAlertsBundle\Check\Delivery;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Helper\TableSeparator;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'security-alerts:check', description: 'Check installed Composer and npm packages for known vulnerabilities, exploited ones first')]
final class CheckCommand extends Command
{
    /** Exit code when a source or lockfile couldn't be read, or the alert couldn't be sent. */
    public const INCOMPLETE = 2;

    public function __construct(private readonly Checker $checker)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('fail-on', null, InputOption::VALUE_REQUIRED, 'Exit with 1 when a finding is at least: exploited, critical, high, medium or any')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Print the report as JSON')
            ->addOption('notify', null, InputOption::VALUE_NONE, 'Remember findings and send alerts for new ones (what the scheduler runs)')
            ->addOption('fresh', null, InputOption::VALUE_NONE, 'Ignore cached advisories');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $failOn = $input->getOption('fail-on');
        $result = null;

        try {
            $threshold = \is_string($failOn) && $failOn !== '' ? Threshold::parse($failOn) : null;

            if ($input->getOption('notify')) {
                $result = $this->checker->check((bool) $input->getOption('fresh'));
                $report = $result->report;
            } else {
                $report = $this->checker->scan((bool) $input->getOption('fresh'));
            }
        } catch (SecurityAdvisoriesException $e) {
            $io->error($e->getMessage());

            return self::FAILURE;
        }

        if ($input->getOption('json')) {
            $output->writeln((string) json_encode($report, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE), OutputInterface::OUTPUT_RAW);
        } else {
            $this->render($io, $report);
        }

        $deliveryFailed = false;
        if ($result !== null && !$input->getOption('json')) {
            $deliveryFailed = $this->renderDelivery($io, $result);
        } elseif ($result !== null) {
            $deliveryFailed = $result->delivery === Delivery::Failed;
        }

        if ($threshold !== null && $report->failing($threshold) !== []) {
            return self::FAILURE;
        }

        return $report->isComplete() && !$deliveryFailed ? self::SUCCESS : self::INCOMPLETE;
    }

    private function renderDelivery(SymfonyStyle $io, CheckResult $result): bool
    {
        $count = \count($result->announced);

        switch ($result->delivery) {
            case Delivery::Sent:
                $io->success('Sent an alert about '.self::plural('finding', $count).'.');
                break;
            case Delivery::NotConfigured:
                $io->warning('Recorded '.self::plural('finding', $count).' but nobody was told: set security_alerts.notify.recipients (or a chat channel) so alerts reach someone.');
                break;
            case Delivery::Failed:
                $io->warning('Couldn\'t send the alert ('.$result->error.'). '.self::plural('finding', $result->held).' will be announced on the next check.');

                return true;
            case Delivery::None:
                break;
        }

        return false;
    }

    private function render(SymfonyStyle $io, Report $report): void
    {
        $io->newLine();

        if ($report->isClean()) {
            if ($report->packageCount() > 0) {
                $io->success('No known vulnerabilities in '.$this->scope($report).'.');
            }
        } else {
            $rows = [];
            foreach ($report->findings as $i => $finding) {
                if ($i > 0) {
                    $rows[] = new TableSeparator();
                }
                $rows[] = $this->row($finding);
            }

            (new Table($io))
                ->setStyle('box')
                ->setHeaders(['', 'Package', 'Installed', 'Fixed in', 'Advisory'])
                ->setRows($rows)
                ->render();
            $io->newLine();
            foreach ($this->summary($report) as $line) {
                $io->writeln('  '.$line);
            }
            $io->newLine();
        }

        foreach ($report->problems as $problem) {
            $io->warning($problem);
        }
    }

    /**
     * @return list<string>
     */
    private function row(Finding $finding): array
    {
        $title = mb_strlen($finding->title) > 64 ? mb_substr($finding->title, 0, 63).'…' : $finding->title;
        $advisory = OutputFormatterEscape::escape($title);
        $details = array_filter([$finding->cve, $finding->link !== null ? preg_replace('#^https?://(www\.)?#', '', $finding->link) : null]);
        if ($details !== []) {
            $advisory .= "\n<fg=gray>".OutputFormatterEscape::escape(implode(' · ', $details)).'</>';
        }
        if ($finding->exploited !== null) {
            $advisory .= "\n<fg=red>In CISA KEV since ".$finding->exploited->dateAdded->format('Y-m-d')
                .($finding->exploited->dueDate !== null ? ', patch by '.$finding->exploited->dueDate->format('Y-m-d') : '').'</>';
        }

        return [
            $finding->isExploited() ? '<fg=red;options=bold>Exploited</>' : $this->severity($finding->severity),
            OutputFormatterEscape::escape($finding->package).($finding->ecosystem === Ecosystem::Npm ? ' <fg=gray>npm</>' : '').($finding->isDev ? ' <fg=gray>dev</>' : ''),
            OutputFormatterEscape::escape($finding->installed),
            $finding->fixedIn !== null ? '<fg=green>'.OutputFormatterEscape::escape($finding->fixedIn).'</>' : '<fg=gray>–</>',
            $advisory,
        ];
    }

    private function severity(Severity $severity): string
    {
        return match ($severity) {
            Severity::Critical => '<fg=red>Critical</>',
            Severity::High => '<fg=yellow>High</>',
            Severity::Medium => 'Medium',
            Severity::Low, Severity::NotRated => '<fg=gray>'.$severity->label().'</>',
        };
    }

    /**
     * @return list<string>
     */
    private function summary(Report $report): array
    {
        $parts = [];
        foreach ($report->counts() as $kind => $count) {
            $parts[] = $kind === 'exploited'
                ? "<fg=red;options=bold>{$count} exploited in the wild</>"
                : $count.' '.($kind === 'not_rated' ? 'not rated' : $kind);
        }

        $lines = [self::plural('vulnerability', \count($report->findings), 'vulnerabilities').' in '.self::plural('package', \count($report->affectedPackages())).': '.implode(', ', $parts).'.'];

        $worst = $report->worst();
        if ($worst !== null && $worst->isExploited()) {
            $lines[] = '<options=bold>Update '.OutputFormatterEscape::escape($worst->package).($worst->fixedIn !== null && !str_starts_with($worst->fixedIn, '>') ? ' to '.OutputFormatterEscape::escape($worst->fixedIn).' or later' : '').' today.</>';
        }

        $lines[] = '<fg=gray>Checked '.$this->scope($report).'.</>';

        return $lines;
    }

    private function scope(Report $report): string
    {
        $parts = [];
        foreach (Ecosystem::cases() as $ecosystem) {
            if (($count = $report->packageCount($ecosystem)) > 0) {
                $parts[] = $count.' '.$ecosystem->label();
            }
        }

        return implode(' and ', $parts).' '.($report->packageCount() === 1 ? 'package' : 'packages');
    }

    private static function plural(string $word, int $count, ?string $plural = null): string
    {
        return $count.' '.($count === 1 ? $word : $plural ?? $word.'s');
    }
}
