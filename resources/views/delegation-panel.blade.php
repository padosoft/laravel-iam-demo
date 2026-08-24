{{-- Delegated access (laravel-iam-agents): the acceptance walkthrough of the delegation loop.
     $delegation comes from DelegationDemoController::panelState(). --}}
@php $dflash = session('delegation_flash'); @endphp

<h2>Delegated access &nbsp;<span style="color:var(--mut);font-weight:400;font-size:13px;">— an AI agent acts for you, without ever holding your token (<code>laravel-iam-agents</code>)</span></h2>

@if ($dflash)
    <div class="card" style="margin-bottom:16px;border-color:{{ ($dflash['ok'] ?? false) ? 'rgba(52,211,153,.5)' : 'rgba(248,113,113,.5)' }};">
        <strong style="color:{{ ($dflash['ok'] ?? false) ? 'var(--green)' : 'var(--red)' }};">{{ ($dflash['ok'] ?? false) ? 'OK' : 'REFUSED' }} · {{ $dflash['step'] ?? '' }}</strong>
        <div style="color:var(--mut);font-size:13px;margin-top:6px;">{{ $dflash['detail'] ?? '' }}</div>
    </div>
@endif

@guest
    <div class="card"><p style="margin:0;color:var(--mut);">Log in first (panel above) — delegation starts from a real user session: the consent is step-up bound to it, and every exchange re-checks that the session is still alive.</p></div>
@else
<div class="grid" style="grid-template-columns:1fr 1fr; gap:16px;">
    {{-- STEP 1 — the agent becomes a first-class identity --}}
    <div class="card">
        <h3 style="margin:0 0 8px;">1 · Register the agent</h3>
        <p style="color:var(--mut);font-size:13px;margin:0 0 10px;">Creates + approves <strong>{{ \App\Http\Controllers\DelegationDemoController::AGENT_NAME }}</strong>: an OAuth client with <em>only</em> the RFC 8693 token-exchange grant, and its own PDP permission — <code>invoices.view</code>, nothing else.</p>
        <form method="POST" action="{{ route('demo.delegation.setup') }}">@csrf<button type="submit">Register &amp; approve agent</button></form>
        @if ($delegation['agent'])
            <div class="dec exp" style="border:0;padding:8px 0 0;">agent: {{ $delegation['agent']['id'] }} · status: {{ $delegation['agent']['status'] }} · max_scopes: {{ implode(', ', $delegation['agent']['max_scopes'] ?? []) }}</div>
        @endif
    </div>

    {{-- STEP 2 — consent through the module's OWN self-service endpoints --}}
    <div class="card">
        <h3 style="margin:0 0 8px;">2 · Consent (step-up bound)</h3>
        <p style="color:var(--mut);font-size:13px;margin:0 0 10px;">Calls the module's real endpoints at <code>/iam/me/delegations</code>: the challenge is <strong>bound</strong> to (agent, scopes, ttl, purpose) — change anything after the screen and it's refused. Demo step-up code: <code>{{ $delegation['stepup_code'] ?? 'n/a' }}</code> <span style="font-size:12px;">(in production: your TOTP/passkey)</span>.</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button type="button" onclick="delegationConsent()">Open challenge &amp; consent</button>
        </div>
        <div id="consent-out" class="dec exp" style="border:0;padding:8px 0 0;"></div>
        @if ($delegation['grants'])
            <div style="margin-top:8px;">
                @foreach ($delegation['grants'] as $g)
                    <div class="dec exp" style="border:0;padding:2px 0;">grant {{ $g['id'] }} · {{ implode(' ', $g['scopes'] ?? []) }} · {{ $g['status'] }} · consent AAL: {{ $g['consent_aal'] ?? '—' }}</div>
                @endforeach
            </div>
        @endif
    </div>

    {{-- STEP 3 — the exchange --}}
    <div class="card">
        <h3 style="margin:0 0 8px;">3 · RFC 8693 exchange</h3>
        <p style="color:var(--mut);font-size:13px;margin:0 0 10px;">The orchestrator (server-side) presents <em>your</em> token as <code>subject_token</code> and the agent's credential, on the app's real <code>/oauth/token</code>. Out comes a token with <strong>two identities</strong> — <code>sub</code> = you, <code>act</code> = the agent — TTL ≤ 300s, non-refreshable.</p>
        <form method="POST" action="{{ route('demo.delegation.exchange') }}">@csrf<button type="submit">Exchange</button></form>
        @if ($delegation['token'])
            <div class="dec exp" style="border:0;padding:8px 0 0;white-space:pre-wrap;">{{ json_encode($delegation['token']['claims'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) }}</div>
        @endif
    </div>

    {{-- STEP 4 — the agent calls a REAL protected API (the proof) --}}
    <div class="card">
        <h3 style="margin:0 0 8px;">4 · The agent calls the protected API</h3>
        <p style="color:var(--mut);font-size:13px;margin:0 0 10px;">The routes under <code>/demo/agent-api</code> are guarded by <code>iam.can.delegated</code> (laravel-iam-client): <strong>only</strong> a delegated token minted by the exchange gets in. No token ⇒ <code>401</code> · <code>invoices.view</code> ⇒ <code>200</code> · <code>invoices.create</code> ⇒ <code>403</code> — the USER holds it, the agent doesn't: minimal intersection, enforced by the middleware, not by app code.</p>
        <form method="POST" action="{{ route('demo.delegation.call') }}">@csrf<button type="submit">Call the agent API (3 requests)</button></form>
        @if (!empty($delegation['calls']))
            <div class="dec exp" style="border:0;padding:8px 0 0;">
                no token → {{ $delegation['calls']['no_token']['status'] }} ·
                GET view → {{ $delegation['calls']['view']['status'] }} ·
                POST create → {{ $delegation['calls']['create']['status'] }}
            </div>
            @if (!empty($delegation['calls']['view']['body']['iam_delegation']))
                <div class="dec exp" style="border:0;padding:4px 0 0;white-space:pre-wrap;">Context on the 200: {{ json_encode($delegation['calls']['view']['body']['iam_delegation'], JSON_UNESCAPED_SLASHES) }}</div>
            @endif
        @endif
    </div>

    {{-- STEP 5 + 6 — intersection via the PDP (decision ids), then revoke --}}
    <div class="card">
        <h3 style="margin:0 0 8px;">5 · PDP decision ids &nbsp;·&nbsp; 6 · Revoke</h3>
        <p style="color:var(--mut);font-size:13px;margin:0 0 10px;">Same intersection, asked to the PDP directly (both sub-decision ids cited). Then revoke and press Exchange again: <code>invalid_grant</code>.</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <form method="POST" action="{{ route('demo.delegation.check') }}">@csrf<button type="submit">Run delegated checks</button></form>
            <form method="POST" action="{{ route('demo.delegation.revoke') }}">@csrf<button type="submit">Revoke my grant</button></form>
        </div>
    </div>
</div>

{{-- The demo log: iam_delegation attached to every [agent-api] line by Laravel Context --}}
@if (!empty($delegation['log_tail']))
    <h2 style="font-size:15px;">Demo log <span style="color:var(--mut);font-weight:400;font-size:12px;">(storage/logs/laravel.log — the middleware's Context rides every line: an agent acts, the sub is a user)</span></h2>
    <div class="card">
        @foreach ($delegation['log_tail'] as $line)
            <div class="dec exp" style="border:0;padding:3px 0;word-break:break-all;">{{ $line }}</div>
        @endforeach
    </div>
@endif

{{-- The audit stream: every exchange (issued AND refused), grant create/revoke — both identities on each event --}}
@if ($delegation['audit'])
    <h2 style="font-size:15px;">Delegation audit stream <span style="color:var(--mut);font-weight:400;font-size:12px;">(hash-chained, <code>stream=delegation</code>)</span></h2>
    <div class="card">
        @foreach ($delegation['audit'] as $ev)
            <div class="dec" style="padding:8px 0;">
                <div>
                    <div class="q" style="font-size:13px;">{{ $ev['event_type'] }}</div>
                    <div class="exp">{{ json_encode($ev['metadata'], JSON_UNESCAPED_SLASHES) }}</div>
                </div>
            </div>
        @endforeach
    </div>
@endif

<script>
async function delegationConsent() {
    const out = document.getElementById('consent-out');
    const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json',
                      'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content };
    const payload = { agent_id: @json($delegation['agent']['id'] ?? null), scopes: ['invoices.view'],
                      ttl_seconds: 86400, purpose: 'Read my invoices for the weekly digest' };
    if (!payload.agent_id) { out.textContent = 'Register the agent first.'; return; }

    out.textContent = 'Opening the bound challenge…';
    let r = await fetch('/iam/me/delegations/consent-challenge', { method: 'POST', headers, body: JSON.stringify(payload) });
    let j = await r.json();
    if (!r.ok) { out.textContent = 'Challenge refused: ' + JSON.stringify(j); return; }

    const code = prompt('Step-up verification — enter the demo code (' + @json($delegation['stepup_code'] ?? '') + '):');
    if (!code) { out.textContent = 'Consent aborted.'; return; }

    out.textContent = 'Verifying + creating the grant…';
    r = await fetch('/iam/me/delegations', { method: 'POST', headers,
        body: JSON.stringify({ ...payload, challenge_id: j.data.challenge_id, verification: { code } }) });
    j = await r.json().catch(() => ({}));
    out.textContent = r.status === 201
        ? 'Grant created: ' + j.data.id + ' (one-shot confirmation — reload to see it listed)'
        : 'Consent refused (' + r.status + '): ' + JSON.stringify(j);
    if (r.status === 201) { setTimeout(() => location.reload(), 1200); }
}
</script>
@endguest
