<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Notification;

use Ruvelo\SecurityAdvisories\Finding;

/**
 * The alert as HTML (for email, inline styles only: no template engine
 * needed) and as plain text (email alternative and chat).
 */
final class AlertRenderer
{
    public static function text(Alert $alert): string
    {
        $lines = [$alert->heading(), '', $alert->intro(), ''];

        foreach ([...$alert->exploited, ...$alert->others] as $finding) {
            $lines[] = '- '.$finding->package.' '.$finding->installed.' · '.$finding->severity->label().($finding->isExploited() ? ' · EXPLOITED IN THE WILD' : '').' · '.ucfirst(Alert::fix($finding));
            $lines[] = '  '.$finding->title.($finding->cve !== null ? ' ('.$finding->cve.')' : '');
            if (($link = self::link($finding)) !== null) {
                $lines[] = '  '.$link;
            }
            if ($finding->exploited !== null) {
                $lines[] = '  In CISA\'s catalogue since '.self::date($finding->exploited->dateAdded).($finding->exploited->dueDate !== null ? '; US agencies must patch by '.self::date($finding->exploited->dueDate) : '').'.';
            }
        }

        return implode("\n", [...$lines, '', $alert->footer()])."\n";
    }

    public static function html(Alert $alert): string
    {
        $e = static fn (string $s): string => htmlspecialchars($s, \ENT_QUOTES | \ENT_SUBSTITUTE, 'UTF-8');
        $body = '<h1 style="margin:0 0 12px;font-size:21px;line-height:1.3;letter-spacing:-0.02em;color:#16162A">'.$e($alert->heading()).'</h1>'
            .'<p style="margin:0 0 20px;color:#4B4B63">'.$e($alert->intro()).'</p>';

        foreach ($alert->exploited as $finding) {
            $body .= '<div style="margin:0 0 14px;padding:14px 16px;background:#FFF1F3;border:1px solid #F7C3CB;border-left:4px solid #E5384F;border-radius:10px">'
                .self::finding($finding, $e, true).'</div>';
        }

        if ($alert->others !== []) {
            if ($alert->exploited !== []) {
                $body .= '<h2 style="margin:24px 0 10px;font-size:16px;color:#16162A">'.(\count($alert->others) === 1 ? 'Also new' : 'Also').'</h2>';
            }
            foreach ($alert->others as $finding) {
                $body .= '<div style="margin:0 0 10px;padding:12px 16px;background:#F8F8FC;border:1px solid #E4E4EF;border-radius:10px">'.self::finding($finding, $e, false).'</div>';
            }
        }

        $body .= '<p style="margin:24px 0 0;font-size:13px;color:#74748B">'.$e($alert->footer()).'</p>';

        return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.$e($alert->subject()).'</title></head>'
            .'<body style="margin:0;padding:0;background:#F0F0F7;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.6;color:#16162A">'
            .'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F0F0F7"><tr><td align="center" style="padding:28px 12px">'
            .'<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#FFFFFF;border-radius:14px;overflow:hidden;border:1px solid #E4E4EF">'
            .'<tr><td style="height:3px;line-height:3px;font-size:0;background:#3D4EFF;background-image:linear-gradient(90deg,#3D4EFF,#A78BFA)">&nbsp;</td></tr>'
            .'<tr><td style="padding:28px 28px 30px">'.$body.'</td></tr></table></td></tr></table></body></html>';
    }

    /**
     * @param callable(string): string $e
     */
    private static function finding(Finding $finding, callable $e, bool $urgent): string
    {
        $out = '<div style="font-size:15px"><strong>'.$e($finding->package.' '.$finding->installed).'</strong>'
            .' <span style="color:#74748B">· '.$e($finding->severity->label()).($urgent ? '</span> <span style="color:#E5384F;font-weight:600">· exploited in the wild' : '').'</span></div>'
            .'<div style="margin-top:2px">'.$e($finding->title).($finding->cve !== null ? ' <span style="color:#74748B">· '.$e($finding->cve).'</span>' : '');

        if (($link = self::link($finding)) !== null) {
            $out .= ' · <a href="'.$e($link).'" style="color:#3D4EFF">Advisory</a>';
        }
        $out .= '</div>';

        if ($finding->exploited !== null) {
            $out .= '<div style="margin-top:4px;font-size:13px;color:#4B4B63">In CISA\'s catalogue since '.$e(self::date($finding->exploited->dateAdded))
                .($finding->exploited->dueDate !== null ? '; US agencies must patch by '.$e(self::date($finding->exploited->dueDate)) : '').'.</div>';
        }

        return $out.'<div style="margin-top:6px;font-weight:600;color:'.($urgent ? '#E5384F' : '#167A4A').'">'.$e(ucfirst(Alert::fix($finding))).'.</div>';
    }

    /**
     * Only http(s) links are ever written into a message.
     */
    private static function link(Finding $finding): ?string
    {
        return $finding->link !== null && preg_match('#^https?://#i', $finding->link) === 1 ? $finding->link : null;
    }

    private static function date(\DateTimeImmutable $date): string
    {
        return $date->format('j F Y');
    }
}
