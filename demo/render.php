<?php

declare(strict_types=1);

/*
 * Renders the README previews from the bundle itself: the real command in a
 * kernel fed the recorded feeds of Halyard (a made-up app), and the real alert
 * email. Writes build/terminal.html and build/mail.html; demo/screenshots.sh
 * turns them into art/*.png.
 *
 *   php demo/render.php build
 */

use Ruvelo\SecurityAlertsBundle\Check\Checker;
use Ruvelo\SecurityAlertsBundle\Notification\Alert;
use Ruvelo\SecurityAlertsBundle\Notification\AlertRenderer;
use Ruvelo\SecurityAlertsBundle\Tests\Support\TestKernel;
use Ruvelo\SecurityAlertsBundle\Tests\Support\ValtryFake;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Filesystem\Filesystem;

require __DIR__.'/../vendor/autoload.php';

$out = rtrim($argv[1] ?? 'build', '/');
$fs = new Filesystem();
$fs->mkdir($out);

$project = sys_get_temp_dir().'/halyard-'.bin2hex(random_bytes(4));
$fs->mkdir($project);
copy(__DIR__.'/../tests/Fixtures/composer.lock', $project.'/composer.lock');
copy(__DIR__.'/../tests/Fixtures/package-lock.json', $project.'/package-lock.json');

putenv('COLUMNS=150');
$kernel = new TestKernel(
    ['project_dir' => $project, 'valtry_url' => ValtryFake::URL, 'cache_pool' => null, 'notify' => ['app_name' => 'Halyard'], 'state' => ['directory' => $project.'/state']],
    ['mailer' => ['dsn' => 'null://null']],
    variant: 'demo',
);
$application = new Application($kernel);
$application->setAutoExit(false);

$output = new BufferedOutput(OutputInterface::VERBOSITY_NORMAL, true);
$application->run(new ArrayInput(['command' => 'security-alerts:check']), $output);
$terminal = ansiToHtml($output->fetch());

$checker = $kernel->getContainer()->get('security_alerts.checker');
\assert($checker instanceof Checker);
$alert = new Alert('Halyard', \array_slice($checker->scan()->findings, 0, 6));

$html = AlertRenderer::html($alert);
preg_match('#<body[^>]*>(.*)</body>#s', $html, $body);

file_put_contents($out.'/terminal.html', terminalPage($terminal));
file_put_contents($out.'/mail.html', mailPage($alert->subject(), $body[1] ?? ''));

$kernel->shutdown();
$kernel->cleanup();
$fs->remove($project);

fwrite(\STDOUT, "Wrote $out/terminal.html and $out/mail.html\n");

/**
 * The few ANSI codes Symfony's console writes, as spans.
 */
function ansiToHtml(string $ansi): string
{
    $html = '';
    $fg = null;
    $bg = null;
    $bold = false;
    $names = ['30' => 'black', '31' => 'red', '32' => 'green', '33' => 'yellow', '34' => 'blue', '37' => 'white', '90' => 'gray'];
    $backgrounds = ['41' => 'bg-red', '42' => 'bg-green', '43' => 'bg-yellow', '44' => 'bg-blue'];

    foreach (preg_split('/(\e\[[\d;]*m)/', $ansi, -1, \PREG_SPLIT_DELIM_CAPTURE) ?: [] as $part) {
        if (preg_match('/^\e\[([\d;]*)m$/', $part, $m) === 1) {
            foreach (explode(';', $m[1]) as $code) {
                match (true) {
                    $code === '0' || $code === '' => [$fg, $bg, $bold] = [null, null, false],
                    $code === '1' => $bold = true,
                    $code === '22' => $bold = false,
                    $code === '39' => $fg = null,
                    $code === '49' => $bg = null,
                    isset($names[$code]) => $fg = $names[$code],
                    isset($backgrounds[$code]) => $bg = $backgrounds[$code],
                    default => null,
                };
            }

            continue;
        }

        $text = htmlspecialchars($part, \ENT_QUOTES);
        $classes = array_filter([$fg, $bg, $bold ? 'b' : null]);
        $html .= $classes === [] || trim($part) === '' && $bg === null ? $text : '<span class="'.implode(' ', $classes).'">'.$text.'</span>';
    }

    return rtrim($html)."\n";
}

function terminalPage(string $terminal): string
{
    return <<<HTML
        <!doctype html><html lang="en"><head><meta charset="utf-8"><title>Terminal</title>
        <style>
        :root { --night: #11111c; --text: #e4e4ef; }
        * { box-sizing: border-box; }
        body { margin: 0; padding: 28px; background: linear-gradient(135deg, #3d4eff 0%, #a78bfa 100%); font-family: ui-monospace, "Geist Mono", "SF Mono", Menlo, Consolas, "DejaVu Sans Mono", monospace; }
        .term { background: var(--night); border-radius: 14px; box-shadow: 0 24px 60px rgba(17,17,28,.45); overflow: hidden; width: max-content; margin: 0 auto; }
        .head { display: flex; gap: 7px; align-items: center; padding: 12px 16px; background: #171725; border-bottom: 1px solid #2a2a3f; }
        .head i { width: 11px; height: 11px; border-radius: 50%; background: #3a3a55; display: block; }
        .head span { margin-left: 10px; color: #8787a3; font-size: 12px; font-family: system-ui, sans-serif; }
        pre { margin: 0; padding: 18px 22px 22px; color: var(--text); font-size: 13px; line-height: 1.28; font-family: inherit; }
        .prompt { color: #8f9bff; }
        .red { color: #ff6b80; } .green { color: #74d6a2; } .yellow { color: #f5c26b; } .blue { color: #8f9bff; } .gray { color: #8787a3; } .white { color: #fff; } .black { color: #11111c; }
        .bg-yellow { background: #f5c26b; } .bg-red { background: #ff6b80; } .bg-green { background: #74d6a2; } .bg-blue { background: #8f9bff; }
        .b { font-weight: 700; }
        </style></head><body>
        <div class="term"><div class="head"><i></i><i></i><i></i><span>halyard — bash</span></div>
        <pre><span class="prompt">\$</span> bin/console security-alerts:check
        {$terminal}</pre></div>
        </body></html>
        HTML;
}

function mailPage(string $subject, string $body): string
{
    $subject = htmlspecialchars($subject, \ENT_QUOTES);

    return <<<HTML
        <!doctype html><html lang="en"><head><meta charset="utf-8"><title>Mail</title>
        <style>
        body { margin: 0; padding: 32px; background: linear-gradient(135deg, #3d4eff 0%, #a78bfa 100%); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        .client { max-width: 760px; margin: 0 auto; background: #fff; border-radius: 14px; overflow: hidden; box-shadow: 0 24px 60px rgba(17,17,28,.35); }
        .meta { padding: 18px 24px; border-bottom: 1px solid #e4e4ef; background: #f8f8fc; color: #16162a; }
        .meta h1 { margin: 0 0 8px; font-size: 18px; letter-spacing: -0.02em; }
        .meta p { margin: 0; font-size: 13px; color: #4b4b63; line-height: 1.6; }
        .meta b { color: #74748b; font-weight: 500; display: inline-block; width: 48px; }
        .body { background: #f0f0f7; }
        </style></head><body>
        <div class="client"><div class="meta"><h1>{$subject}</h1>
        <p><b>From</b> Halyard alerts &lt;alerts@halyard.example&gt;<br><b>To</b> ops@halyard.example</p></div>
        <div class="body">{$body}</div></div>
        </body></html>
        HTML;
}
