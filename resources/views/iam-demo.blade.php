<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Laravel IAM — Demo</title>
    <style>
        :root { --bg:#0b0f17; --card:#131a26; --line:#1f2937; --ink:#e5e7eb; --mut:#9ca3af; --teal:#2dd4bf; --red:#f87171; --green:#34d399; }
        * { box-sizing:border-box; }
        body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif; }
        .wrap { max-width:1080px; margin:0 auto; padding:32px 20px 64px; }
        header h1 { margin:0 0 4px; font-size:28px; letter-spacing:-.02em; }
        header p { margin:0; color:var(--mut); }
        .pill { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:600; }
        .pill.ok { background:rgba(52,211,153,.15); color:var(--green); }
        .grid { display:grid; gap:16px; }
        .stats { grid-template-columns:repeat(3,1fr); margin:24px 0; }
        .card { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:18px 20px; }
        .stat .n { font-size:34px; font-weight:700; color:var(--teal); }
        .stat .l { color:var(--mut); font-size:13px; text-transform:uppercase; letter-spacing:.06em; }
        h2 { font-size:18px; margin:28px 0 12px; }
        .dec { display:flex; align-items:flex-start; gap:14px; padding:14px 0; border-bottom:1px solid var(--line); }
        .dec:last-child { border-bottom:0; }
        .badge { flex:0 0 auto; min-width:64px; text-align:center; padding:6px 10px; border-radius:8px; font-weight:700; font-size:13px; }
        .badge.allow { background:rgba(52,211,153,.15); color:var(--green); border:1px solid rgba(52,211,153,.4); }
        .badge.deny  { background:rgba(248,113,113,.13); color:var(--red);  border:1px solid rgba(248,113,113,.4); }
        .dec .q { font-weight:600; }
        .dec .why { color:var(--mut); font-size:13px; }
        .dec .exp { color:var(--mut); font-size:12.5px; margin-top:4px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
        ul.lst { list-style:none; margin:0; padding:0; columns:2; column-gap:24px; }
        ul.lst li { padding:3px 0; color:var(--mut); font-size:13.5px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; break-inside:avoid; }
        .pkg { display:flex; justify-content:space-between; gap:16px; padding:9px 0; border-bottom:1px solid var(--line); }
        .pkg:last-child { border-bottom:0; }
        .pkg code { color:var(--teal); }
        .pkg span { color:var(--mut); font-size:13px; text-align:right; }
        footer { margin-top:36px; color:var(--mut); font-size:13px; text-align:center; }
        a { color:var(--teal); }
    </style>
</head>
<body>
<div class="wrap">
    <header>
        <h1>Laravel IAM — Demo &nbsp;<span class="pill ok">all packages live</span></h1>
        <p>The full Laravel IAM ecosystem installed from Packagist and booted in one Laravel app.</p>
    </header>

    <div class="grid stats">
        <div class="card stat"><div class="n">{{ count($packages) }}</div><div class="l">Packages installed</div></div>
        <div class="card stat"><div class="n">{{ $commands->count() }}</div><div class="l">IAM artisan commands</div></div>
        <div class="card stat"><div class="n">{{ $tables->count() }}</div><div class="l">IAM tables migrated</div></div>
    </div>

    @php $reg = session('registered'); @endphp
    <h2>Try it &nbsp;<span style="color:var(--mut);font-weight:400;font-size:13px;">— onboard this app, then log in and assume IAM-decided grants</span></h2>

    <div class="grid" style="grid-template-columns:1fr 1fr; gap:16px;">
        {{-- STEP 1 — register this app in IAM (mint the OAuth client + one-time secret) --}}
        <div class="card">
            <h3 style="margin:0 0 8px;">1 · Register this app in IAM</h3>
            <p style="color:var(--mut);font-size:13px;margin:0 0 12px;">Applies the committed <code>iam-manifest.json</code> — IAM creates the app's permission catalog, its role, and its OAuth client, and issues a client secret <strong>once</strong>.</p>
            <form method="POST" action="{{ route('demo.register') }}">
                @csrf
                <button type="submit" data-test="register-app" style="background:var(--acc,#0b7285);color:#fff;border:0;border-radius:8px;padding:10px 16px;font-weight:600;cursor:pointer;">Register app in IAM</button>
            </form>
            @if ($reg)
                <div class="card" style="margin-top:12px;background:#0d1117;">
                    <div class="dec"><span class="badge allow">DONE</span><div><div class="q">client_id: <code>{{ $reg['client_id'] }}</code></div></div></div>
                    @if ($reg['client_secret'])
                        <p style="margin:8px 0 4px;color:var(--mut);font-size:13px;">Your client secret — shown ONCE. Paste it into your app's <code>.env</code>:</p>
                        <pre data-test="secret" style="white-space:pre-wrap;background:#010409;padding:10px;border-radius:6px;font-size:12px;">IAM_CLIENT_MODE=http
IAM_CLIENT_BASE_URL={{ url('/api/iam/v1') }}
IAM_CLIENT_ID={{ $reg['client_id'] }}
IAM_CLIENT_SECRET={{ $reg['client_secret'] }}</pre>
                        <p style="margin:4px 0 0;color:var(--mut);font-size:12px;">The SDK follows automatic rotations from here — you never touch this secret again.</p>
                    @endif
                </div>
            @elseif ($demoClientId)
                <p style="margin-top:10px;color:var(--mut);font-size:12px;">Already registered as <code>{{ $demoClientId }}</code>. Re-registering re-applies the manifest and re-issues the secret.</p>
            @endif
        </div>

        {{-- STEP 2 — log in against IAM and see the grants IAM decides --}}
        <div class="card">
            <h3 style="margin:0 0 8px;">2 · Log in against IAM</h3>
            @if ($me)
                <p style="margin:0 0 8px;">Logged in as <strong>{{ $me->email }}</strong> — these are the grants <em>IAM</em> decides for you:</p>
                @foreach ($myGrants as $g)
                    <div class="dec" data-test="my-grant"><span class="badge {{ $g['allowed'] ? 'allow' : 'deny' }}">{{ $g['allowed'] ? 'ALLOW' : 'DENY' }}</span><div><div class="q">{{ $g['permission'] }}</div></div></div>
                @endforeach
                <form method="POST" action="{{ route('demo.logout') }}" style="margin-top:12px;">@csrf<button type="submit" style="background:transparent;color:var(--mut);border:1px solid var(--mut);border-radius:8px;padding:8px 14px;cursor:pointer;">Log out</button></form>
            @else
                <p style="color:var(--mut);font-size:13px;margin:0 0 12px;">Sign in as the seeded operator (<code>{{ $demoCreds['email'] }}</code> / <code>{{ $demoCreds['password'] }}</code>) to see the PDP decide your grants in real time.</p>
                @error('email')<p style="color:#f87171;font-size:13px;">{{ $message }}</p>@enderror
                <form method="POST" action="{{ route('demo.login') }}" style="display:grid;gap:8px;max-width:320px;">
                    @csrf
                    <input name="email" type="email" value="{{ old('email', $demoCreds['email']) }}" placeholder="email" data-test="login-email" style="padding:9px;border-radius:6px;border:1px solid #30363d;background:#010409;color:#e6edf3;">
                    <input name="password" type="password" value="{{ $demoCreds['password'] }}" placeholder="password" data-test="login-password" style="padding:9px;border-radius:6px;border:1px solid #30363d;background:#010409;color:#e6edf3;">
                    <button type="submit" data-test="login-submit" style="background:var(--acc,#0b7285);color:#fff;border:0;border-radius:8px;padding:10px 16px;font-weight:600;cursor:pointer;">Log in against IAM</button>
                </form>
            @endif
        </div>
    </div>

    <h2 style="margin-top:20px;">Live PDP decisions <span style="color:var(--mut);font-weight:400;font-size:13px;">— real-time checks through laravel-iam-server's NativeSqlEngine</span></h2>
    <div class="card">
        @foreach ($decisions as $d)
            @php($allowed = $d['decision']['allowed'])
            <div class="dec" data-test="decision">
                <span class="badge {{ $allowed ? 'allow' : 'deny' }}">{{ $allowed ? 'ALLOW' : 'DENY' }}</span>
                <div>
                    <div class="q">{{ $d['label'] }}</div>
                    <div class="why">{{ $d['note'] }}</div>
                    <div class="exp">{{ $d['decision']['explanation'][count($d['decision']['explanation']) - 1] ?? '' }}</div>
                </div>
            </div>
        @endforeach
    </div>
    <p style="color:var(--mut);font-size:13px;">Default-deny + deny-overrides, fully fail-closed: only the explicitly granted permission resolves to <em>allow</em>.</p>

    <h2>Installed packages</h2>
    <div class="card">
        @foreach ($packages as $name => $desc)
            <div class="pkg"><code>{{ $name }}</code><span>{{ $desc }}</span></div>
        @endforeach
    </div>

    <div class="grid" style="grid-template-columns:1fr 1fr; margin-top:16px;">
        <div>
            <h2>IAM commands</h2>
            <div class="card"><ul class="lst">@foreach ($commands as $c)<li>{{ $c }}</li>@endforeach</ul></div>
        </div>
        <div>
            <h2>IAM schema</h2>
            <div class="card"><ul class="lst">@foreach ($tables as $t)<li>{{ $t }}</li>@endforeach</ul></div>
        </div>
    </div>

    <footer>
        Raw JSON at <a href="/iam.json">/iam.json</a> · MIT © Padosoft ·
        <a href="https://github.com/padosoft/laravel-iam-server">Laravel IAM</a>
    </footer>
</div>
</body>
</html>
