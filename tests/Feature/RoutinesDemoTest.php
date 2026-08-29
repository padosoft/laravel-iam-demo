<?php

namespace Tests\Feature;

use App\Routines\InvoiceReminderTarget;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Gate;
use Padosoft\Routines\Contracts\Escalation\RoutineEscalation;
use Padosoft\Routines\Contracts\Escalation\RoutineEscalator;
use Padosoft\Routines\Models\Routine;
use Padosoft\Routines\Models\RoutineRun;
use Padosoft\Routines\RoutineManager;
use Padosoft\Routines\Scheduling\RoutineDispatcher;
use Tests\TestCase;

/**
 * THE acceptance test of the routines design: create a routine with a mandate → the tick fires it
 * → it meets something the mandate does not cover → it STOPS and the question goes out on a
 * channel → a human answers → the fire RESUMES where it stopped, with the same idempotency key.
 *
 * Plus the negative that the whole design exists to make true: **with no answer, nothing happens.**
 *
 * All in-process, no mocks of the package itself — only the channel is a spy, because there is no
 * Telegram here.
 */
class RoutinesDemoTest extends TestCase
{
    use RefreshDatabase;

    private SpyEscalator $channel;

    protected function setUp(): void
    {
        parent::setUp();

        $this->channel = new SpyEscalator;
        $this->app->instance(RoutineEscalator::class, $this->channel);
        $this->app->forgetInstance(RoutineDispatcher::class);

        foreach (['routines.read', 'routines.write', 'routines.fire', 'routines.approve'] as $ability) {
            Gate::define($ability, fn (?object $user): bool => true);
        }
    }

    /**
     * The routines API sits behind `web` + `auth` in this app, and rightly so: it starts
     * automations. A test that bypassed the guard would be testing a configuration nobody runs.
     */
    private function login(): void
    {
        $this->get('/')->assertOk();   // seeds demo@example.com
        $this->post('/demo/login', ['email' => 'demo@example.com', 'password' => 'password'])
            ->assertRedirect('/');
    }

    private function createRoutine(int $writeOffDays = 365): Routine
    {
        $routine = app(RoutineManager::class)->create([
            'owner' => 'user:1',
            'name' => 'Solleciti fatture',
            'description' => 'Ogni mattina alle 6, nei giorni feriali.',
            'target_type' => 'demo.invoice-reminder',
            'target_payload' => ['overdue_days' => 30, 'write_off_days' => $writeOffDays],
            'trigger_kind' => 'cron',
            'cron' => '0 6 * * 1-5',
            'timezone' => 'Europe/Rome',
            'budget_per_run' => 0.50,
        ]);

        // The standing mandate: it may chase, it may NOT write off. That single omission is what
        // the rest of this test is about.
        app(RoutineManager::class)->grantMandate(
            $routine,
            actionClasses: ['invoice.remind'],
            budgetCeiling: 0.50,
            confirmationId: 'stepup_demo',
            aal: 'aal2',
        );

        return $routine->fresh();
    }

    public function test_the_schedule_is_computed_in_the_owners_timezone_not_the_servers(): void
    {
        $routine = $this->createRoutine();

        $preview = app(RoutineManager::class)->preview($routine, 3);

        $this->assertCount(3, $preview);
        foreach ($preview as $when) {
            $this->assertStringEndsWith('06:00', $when, 'six in the morning in Rome, not in UTC');
        }
    }

    public function test_inside_the_mandate_the_routine_runs_alone(): void
    {
        // write_off_days above every invoice: nothing exceeds the mandate, so nobody is disturbed.
        $routine = $this->createRoutine(writeOffDays: 10_000);
        $routine->forceFill(['next_run_at' => now()->subMinute()])->save();

        app(RoutineDispatcher::class)->tick();

        $run = RoutineRun::query()->latest('created_at')->firstOrFail();
        $this->assertSame('succeeded', $run->outcome);
        $this->assertSame('scheduled', $run->reason);
        $this->assertStringContainsString('reminder', (string) $run->message);
        $this->assertSame([], $this->channel->sent, 'nobody should have been contacted');
    }

    public function test_outside_the_mandate_it_stops_and_the_question_leaves_on_a_channel(): void
    {
        $routine = $this->createRoutine();      // INV-003 is 400 days overdue
        $routine->forceFill(['next_run_at' => now()->subMinute()])->save();

        app(RoutineDispatcher::class)->tick();

        $run = RoutineRun::query()->latest('created_at')->firstOrFail();

        // Not failed (nothing is broken) and not succeeded (nothing was done).
        $this->assertSame('paused', $run->outcome);
        $this->assertSame('invoice.write_off', $run->action_class);
        $this->assertNotNull($run->escalated_at, 'the question must have gone out');
        $this->assertNull($run->escalation_error);

        $this->assertCount(1, $this->channel->sent);
        $escalation = $this->channel->sent[0];
        $this->assertSame('user:1', $escalation->owner);
        $this->assertSame($run->id, $escalation->runId);
        // The facts a person needs to decide — and nothing else: this crosses networks we do not own.
        $this->assertSame('INV-003', $escalation->facts['invoice']);
        $this->assertSame(1240.0, $escalation->facts['amount']);
    }

    public function test_with_no_answer_nothing_happens(): void
    {
        // The negative the whole design exists to make true. A routine that "eventually goes ahead"
        // would make the mandate decorative.
        $routine = $this->createRoutine();
        $routine->forceFill(['next_run_at' => now()->subMinute()])->save();

        app(RoutineDispatcher::class)->tick();
        app(RoutineDispatcher::class)->tick();      // another tick. Still nobody answered.
        app(RoutineDispatcher::class)->tick();

        $this->assertSame(1, RoutineRun::query()->where('outcome', 'paused')->count());
        $this->assertSame(0, RoutineRun::query()->where('outcome', 'succeeded')->count());
        // A pause is not retried on a backoff: it is waiting for a person.
        $this->assertNull(RoutineRun::query()->latest('created_at')->first()?->retry_at);
    }

    public function test_the_approval_resumes_the_fire_with_the_same_idempotency_key(): void
    {
        $routine = $this->createRoutine();
        $routine->forceFill(['next_run_at' => now()->subMinute()])->save();
        app(RoutineDispatcher::class)->tick();

        $paused = RoutineRun::query()->where('outcome', 'paused')->firstOrFail();

        $resumed = app(RoutineManager::class)->resolve($paused, approved: true, resolvedBy: 'user:1', note: 'Ok, chiudila.');

        $this->assertSame('succeeded', $resumed->outcome);
        $this->assertSame('resumed', $resumed->reason);
        // Same key: for the target this is the SAME work, so it resumes instead of re-sending the
        // reminders it had already sent before stopping.
        $this->assertSame($paused->idempotency_key, $resumed->idempotency_key);
        $this->assertStringContainsString('written off', (string) $resumed->message);
        $this->assertStringContainsString('user:1', (string) $resumed->message);
    }

    public function test_a_rejection_closes_it_as_skipped_with_the_reason_and_does_not_retry(): void
    {
        $routine = $this->createRoutine();
        $routine->forceFill(['next_run_at' => now()->subMinute()])->save();
        app(RoutineDispatcher::class)->tick();

        $paused = RoutineRun::query()->where('outcome', 'paused')->firstOrFail();

        $resolved = app(RoutineManager::class)->resolve($paused, approved: false, resolvedBy: 'user:1', note: 'Il cliente ha promesso di pagare.');

        // Nothing broke: someone decided no. `failed` would retry it.
        $this->assertSame('skipped', $resolved->outcome);
        $this->assertNull($resolved->retry_at);
        $this->assertStringContainsString('Il cliente ha promesso', (string) $resolved->message);
    }

    public function test_the_mandate_stops_covering_a_payload_edited_after_the_consent(): void
    {
        // The same principle as PSD2 dynamic linking: the consent was for THAT configuration.
        $routine = $this->createRoutine();
        $manager = app(RoutineManager::class);

        $this->assertTrue($manager->mandateCovers($routine));

        $manager->update($routine, ['target_payload' => ['overdue_days' => 1, 'write_off_days' => 2]]);

        $this->assertFalse($manager->mandateCovers($routine->fresh()));
    }

    public function test_the_admin_api_shows_the_queue_of_what_is_waiting_for_a_human(): void
    {
        $routine = $this->createRoutine();
        $routine->forceFill(['next_run_at' => now()->subMinute()])->save();
        app(RoutineDispatcher::class)->tick();

        $this->login();

        $body = $this->getJson('/api/routines/v1/attention')->assertOk()->json('data');

        $this->assertCount(1, $body);
        $this->assertSame('Solleciti fatture', $body[0]['routine_name']);
        $this->assertTrue($body[0]['can_approve']);
        // The readable text is composed by the SERVER, so the panel, the CLI and the audit all
        // say the same thing.
        $this->assertStringContainsString('INV-003', $body[0]['question']);

        $detail = $this->getJson('/api/routines/v1/routines/'.$routine->id)->assertOk()->json('data');
        $this->assertSame('Ogni giorno feriale alle 06:00', $detail['schedule_human']);
        $this->assertSame('user:1', $detail['owner']);
        $this->assertSame(['invoice.remind'], $detail['mandate']['action_classes']);
        $this->assertTrue($detail['mandate']['payload_matches']);
    }

    public function test_the_health_endpoint_diagnoses_a_scheduler_that_is_not_running(): void
    {
        $this->login();

        $data = $this->getJson('/api/routines/v1/health')->assertOk()->json('data');

        $this->assertFalse($data['tick_healthy']);
        $this->assertStringContainsString('schedule:run', (string) $data['tick_diagnosis']);
    }

    public function test_the_target_registry_is_populated_from_the_application(): void
    {
        $this->login();

        $targets = collect($this->getJson('/api/routines/v1/targets')->assertOk()->json('data'));

        $demo = $targets->firstWhere('type', 'demo.invoice-reminder');
        $this->assertNotNull($demo);
        $this->assertTrue($demo['registered']);
        $this->assertSame('Invoice reminders', $demo['label']);
        $this->assertContains('invoice.write_off', $demo['action_classes']);
        // The panel can draw a form for a type it has never heard of.
        $this->assertArrayHasKey('overdue_days', (array) $demo['fields']);
    }

    public function test_an_invalid_payload_fails_while_a_human_is_at_the_form(): void
    {
        $this->login();

        $this->postJson('/api/routines/v1/routines', [
            'owner' => 'user:1',
            'name' => 'Rotta',
            'target_type' => 'demo.invoice-reminder',
            'target_payload' => ['overdue_days' => 0],
            'trigger_kind' => 'cron',
            'cron' => '0 6 * * *',
            'timezone' => 'Europe/Rome',
        ])->assertStatus(422)->assertJsonPath('errors.overdue_days.0', 'Give a number of days, at least 1.');
    }

    public function test_the_invoice_fixture_still_has_one_beyond_any_reasonable_mandate(): void
    {
        // Guards the fixture the rest of this test file depends on: if someone lowers INV-003's
        // age, half these tests would pass for the wrong reason.
        $oldest = max(array_column(InvoiceReminderTarget::INVOICES, 'days'));
        $this->assertGreaterThan(365, $oldest);
    }
}

/** Stands in for laravel-rebel-channels: there is no Telegram in a test suite. */
class SpyEscalator implements RoutineEscalator
{
    /** @var list<RoutineEscalation> */
    public array $sent = [];

    public function escalate(RoutineEscalation $escalation): void
    {
        $this->sent[] = $escalation;
    }
}
