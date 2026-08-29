<?php

namespace App\Routines;

use Illuminate\Support\Facades\Log;
use Padosoft\Routines\Contracts\Consent\MandateExceeded;
use Padosoft\Routines\Contracts\Execution\RoutineExecution;
use Padosoft\Routines\Contracts\Target\RoutineTarget;
use Padosoft\Routines\Contracts\Target\TargetDescriptor;
use Padosoft\Routines\Contracts\Target\TargetResult;
use Padosoft\Routines\Contracts\Target\ValidationResult;

/**
 * The demo target: chase overdue invoices.
 *
 * It exists to show the one thing that makes this package different from every other scheduler —
 * what happens when an automation running at 3am meets something it was not authorized to do.
 *
 * Chasing an invoice is harmless, so it runs unattended. Writing one off is not: it moves money,
 * and it is irreversible. The mandate covers `invoice.remind` and not `invoice.write_off`, so when
 * the routine finds an invoice old enough to write off it **stops and asks** — it does not fail
 * (nothing is broken) and it does not proceed (nobody authorized that).
 */
class InvoiceReminderTarget implements RoutineTarget
{
    /** The demo's fake ledger. `days` is how overdue each invoice is. */
    public const INVOICES = [
        ['id' => 'INV-001', 'total' => 120.00, 'days' => 12],
        ['id' => 'INV-002', 'total' => 84.50, 'days' => 45],
        ['id' => 'INV-003', 'total' => 1240.00, 'days' => 400],   // old enough to write off
    ];

    public function type(): string
    {
        return 'demo.invoice-reminder';
    }

    public function descriptor(): TargetDescriptor
    {
        return new TargetDescriptor(
            label: 'Invoice reminders',
            summary: 'Emails a reminder for every overdue invoice, and asks before writing one off.',
            fields: [
                'overdue_days' => [
                    'label' => 'Chase after (days)',
                    'type' => 'number',
                    'required' => true,
                    'help' => 'Invoices overdue by at least this many days get a reminder.',
                ],
                'write_off_days' => [
                    'label' => 'Propose write-off after (days)',
                    'type' => 'number',
                    'required' => false,
                    'help' => 'Beyond this, the routine stops and asks a human.',
                ],
            ],
            actionClasses: ['invoice.remind', 'invoice.write_off'],
            supportsPause: true,
            reportsCost: true,
        );
    }

    public function validate(array $payload): ValidationResult
    {
        $days = $payload['overdue_days'] ?? null;

        // At creation time, while a human is looking at the form.
        if (! is_numeric($days) || (int) $days < 1) {
            return ValidationResult::invalid(['overdue_days' => ['Give a number of days, at least 1.']]);
        }

        return ValidationResult::valid();
    }

    public function fire(RoutineExecution $execution): TargetResult
    {
        $overdueDays = (int) $execution->payload('overdue_days', 30);
        $writeOffDays = (int) $execution->payload('write_off_days', 365);

        // The approval came back: the human said yes to the write-off, so do it now. The fire
        // resumes here rather than starting over — same idempotency key, so the reminders sent
        // before the pause are not sent a second time.
        if ($execution->input('approved_by') !== null) {
            $invoice = $execution->input('resume_token');
            Log::info('[routines-demo] writing off invoice after approval', ['invoice' => $invoice]);

            return TargetResult::succeeded(
                sprintf('Invoice %s written off, approved by %s.', $invoice, $execution->input('approved_by')),
                ['invoice' => $invoice, 'action' => 'write_off'],
                cost: 0.0,
            );
        }

        $reminded = [];
        foreach (self::INVOICES as $invoice) {
            if ($invoice['days'] >= $writeOffDays) {
                // Outside the mandate. Throwing is the natural thing to write here, and the core
                // turns it into a pause rather than a failure — precisely so an implementer who
                // reaches for an exception does not accidentally make the routine give up.
                throw new MandateExceeded('invoice.write_off', [
                    'invoice' => $invoice['id'],
                    'amount' => $invoice['total'],
                    'days_overdue' => $invoice['days'],
                ]);
            }

            if ($invoice['days'] >= $overdueDays) {
                Log::info('[routines-demo] reminder sent', ['invoice' => $invoice['id']]);
                $reminded[] = $invoice['id'];
            }
        }

        if ($reminded === []) {
            // Nothing to do is NOT a success: it is a skip. The distinction shows up in the
            // ledger, and the panel's success rate excludes skips for exactly this reason.
            return TargetResult::skipped('No invoice was overdue enough to chase.');
        }

        return TargetResult::succeeded(
            sprintf('%d reminder(s) sent.', count($reminded)),
            ['invoices' => $reminded],
            cost: count($reminded) * 0.01,
        );
    }
}
