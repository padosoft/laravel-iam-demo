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

    <h2>Live PDP decisions <span style="color:var(--mut);font-weight:400;font-size:13px;">— real-time checks through laravel-iam-server's NativeSqlEngine</span></h2>
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
