// Render HTML. Sin framework y sin build: la consola son ~8 pantallas de
// operador, y un paso de compilacion aqui compraria muy poco a cambio de otra
// cosa que mantener y otra que puede romper el despliegue.
const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

export const html = (strings, ...values) =>
  strings.reduce((out, s, i) => out + s + (i < values.length ? (values[i]?.__raw ?? esc(values[i])) : ''), '');

export const raw = (s) => ({ __raw: s, toString: () => s });

const CSS = `
:root {
  --bg:#0f1115; --surface:#171a21; --surface-2:#1e222b; --border:#2a2f3a;
  --text:#e6e8ec; --dim:#9aa1ad; --ok:#3fb950; --warn:#d29922; --bad:#f85149;
  --accent:#58a6ff; --mono: ui-monospace, SFMono-Regular, Menlo, monospace;
}
* { box-sizing:border-box }
body { margin:0; background:var(--bg); color:var(--text);
  font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif }
a { color:var(--accent); text-decoration:none } a:hover { text-decoration:underline }
header { border-bottom:1px solid var(--border); background:var(--surface);
  padding:.9rem 1.4rem; display:flex; gap:1.4rem; align-items:baseline; flex-wrap:wrap }
header b { font-size:1rem; letter-spacing:.02em }
header nav a { color:var(--dim); margin-right:1rem; font-size:.92rem }
header nav a.on { color:var(--text); font-weight:600 }
main { max-width:1080px; margin:0 auto; padding:1.6rem 1.4rem 4rem }
h1 { font-size:1.35rem; margin:0 0 .3rem } h2 { font-size:1.05rem; margin:2rem 0 .7rem }
p.lead { color:var(--dim); margin:0 0 1.6rem }
.card { background:var(--surface); border:1px solid var(--border); border-radius:10px;
  padding:1rem 1.1rem; margin-bottom:.9rem }
.card h3 { margin:0 0 .15rem; font-size:1rem; display:flex; gap:.6rem; align-items:center; flex-wrap:wrap }
.meta { color:var(--dim); font-size:.85rem; margin:.1rem 0 .6rem }
.mono { font-family:var(--mono); font-size:.85rem }
.pill { font-size:.72rem; padding:.12rem .5rem; border-radius:999px; border:1px solid;
  text-transform:uppercase; letter-spacing:.04em; font-weight:600 }
.pill.ok { color:var(--ok); border-color:#238636aa; background:#2386361a }
.pill.warn { color:var(--warn); border-color:#9e6a03aa; background:#9e6a031a }
.pill.bad { color:var(--bad); border-color:#da3633aa; background:#da36331a }
.pill.dim { color:var(--dim); border-color:var(--border) }
ul.blockers { margin:.4rem 0 0; padding-left:1.1rem; color:var(--warn); font-size:.88rem }
form.inline { display:inline-flex; gap:.4rem; align-items:center; margin:.5rem .5rem 0 0 }
select, input[type=text], input[type=password], textarea {
  background:var(--surface-2); color:var(--text); border:1px solid var(--border);
  border-radius:6px; padding:.35rem .5rem; font:inherit; font-size:.88rem }
textarea { width:100%; min-height:26rem; font-family:var(--mono); font-size:.82rem; line-height:1.5 }
button { background:var(--surface-2); color:var(--text); border:1px solid var(--border);
  border-radius:6px; padding:.35rem .8rem; font:inherit; font-size:.85rem; cursor:pointer }
button:hover { border-color:var(--accent); color:var(--accent) }
button.primary { background:#1f6feb22; border-color:#1f6feb; color:#cfe3ff }
table { width:100%; border-collapse:collapse; font-size:.9rem }
th,td { text-align:left; padding:.45rem .6rem; border-bottom:1px solid var(--border); vertical-align:top }
th { color:var(--dim); font-weight:600; font-size:.8rem; text-transform:uppercase; letter-spacing:.04em }
.flash { border-radius:8px; padding:.7rem 1rem; margin-bottom:1.2rem; font-size:.9rem }
.flash.ok { background:#2386361a; border:1px solid #238636aa }
.flash.bad { background:#da36331a; border:1px solid #da3633aa; white-space:pre-wrap }
.login { max-width:22rem; margin:14vh auto; }
.note { color:var(--dim); font-size:.85rem; margin-top:.4rem }
`;

export function layout({ title, path, body, flash }) {
  const nav = [
    ['/', 'Estado'],
    ['/keys', 'Claves'],
    ['/lists', 'Listas'],
    ['/rps', 'Relying parties'],
    ['/status', 'Revocacion'],
  ]
    .map(([href, label]) => `<a href="${href}" class="${path === href ? 'on' : ''}">${label}</a>`)
    .join('');

  const flashHtml = flash
    ? `<div class="flash ${flash.type}">${esc(flash.message)}</div>`
    : '';

  return `<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${esc(title)} · trust-lab</title><style>${CSS}</style></head>
<body><header><b>trust-lab</b><nav>${nav}</nav>
<span style="margin-left:auto;color:var(--dim);font-size:.82rem">banco de pruebas · no usar con material real</span>
</header><main>${flashHtml}${body}</main></body></html>`;
}

export function loginPage({ error }) {
  return layout({
    title: 'Entrar',
    path: '',
    body: `<div class="login card"><h1>trust-lab</h1>
      <p class="meta">Consola de operacion. Solo escritura autenticada.</p>
      ${error ? `<div class="flash bad">${esc(error)}</div>` : ''}
      <form method="post" action="/login">
        <input type="password" name="password" placeholder="Contrasena" autofocus style="width:100%">
        <button class="primary" style="margin-top:.6rem;width:100%">Entrar</button>
      </form></div>`,
  });
}

const badge = (item) => {
  if (item.blockers.length) return '<span class="pill bad">bloqueada</span>';
  if (!item.published) return '<span class="pill warn">sin publicar</span>';
  if (item.published.stale) return '<span class="pill bad">caducada</span>';
  return '<span class="pill ok">publicada</span>';
};

export function dashboard({ items, rps, signers, flash }) {
  const cards = items
    .map(
      (i) => `<div class="card">
      <h3>${esc(i.title)} ${badge(i)} ${i.nonNormative ? '<span class="pill warn">no normativo</span>' : ''}</h3>
      <div class="meta">${esc(i.type)} · ${i.entries} entrada(s)${
        i.published ? ` · publicada #${i.published.sequence}` : ''
      }${i.published?.nextUpdate ? ` · vence ${esc(new Date(i.published.nextUpdate).toISOString().slice(0, 16).replace('T', ' '))}` : ''}</div>
      ${
        i.blockers.length
          ? `<ul class="blockers">${i.blockers.map((b) => `<li>${esc(b)}</li>`).join('')}</ul>`
          : `<form class="inline" method="post" action="/lists/${encodeURIComponent(i.id)}/build">
               <select name="signer">${i.signers.map((s) => `<option>${esc(s)}</option>`).join('')}</select>
               <button class="primary">Emitir</button></form>
             <span class="mono" style="color:var(--dim)">${esc(i.url ?? '')}</span>`
      }
    </div>`,
    )
    .join('');

  const rpRows = rps
    .map(
      (rp) => `<tr><td><a href="/rps/${encodeURIComponent(rp.id)}">${esc(rp.legalName ?? rp.id)}</a></td>
      <td>${rp.problems.length ? `<span class="pill bad">${rp.problems.length} problema(s)</span>` : '<span class="pill ok">valida</span>'}</td>
      <td>${rp.services.map((s) => esc(s.name)).join(', ')}</td>
      <td>${rp.services.reduce((n, s) => n + s.uses.length, 0)}</td></tr>`,
    )
    .join('');

  return layout({
    title: 'Estado',
    path: '/', flash,
    body: `<h1>Estado del marco de confianza</h1>
    <p class="lead">Que se puede emitir ya, y que lo impide. El orden no es una
    secuencia: es el grafo de dependencias del marco entero.</p>
    ${
      signers.length
        ? ''
        : `<div class="flash bad">No hay ningun firmante de listas. Sin el, ninguna lista se puede emitir: crea uno en <a href="/keys">Claves</a>.</div>`
    }
    <h2>Listas</h2>${cards || '<p class="meta">No hay ninguna lista definida.</p>'}
    <h2>Relying parties</h2>
    <table><tr><th>Entidad</th><th>Registro</th><th>Servicios</th><th>Finalidades</th></tr>${rpRows}</table>`,
  });
}

export function rpsPage({ rps, flash }) {
  return layout({
    title: 'Relying parties', path: '/rps', flash,
    body: `<h1>Relying parties</h1>
    <p class="lead">Cada entidad registrada, con sus servicios y sus finalidades.
    Un access certificate por servicio; un registration certificate por finalidad.</p>
    <table><tr><th>Entidad</th><th>Registro</th><th>Servicios</th><th>Finalidades</th></tr>
    ${rps
      .map(
        (rp) => `<tr><td><a href="/rps/${encodeURIComponent(rp.id)}">${esc(rp.legalName ?? rp.id)}</a></td>
        <td>${rp.problems.length ? `<span class="pill bad">${rp.problems.length} problema(s)</span>` : '<span class="pill ok">valida</span>'}</td>
        <td>${rp.services.map((s) => esc(s.name)).join(', ')}</td>
        <td>${rp.services.reduce((n, s) => n + s.uses.length, 0)}</td></tr>`,
      )
      .join('')}</table>`,
  });
}

export function keysPage({ keys, signers, schemes, flash }) {
  const rows = keys
    .map(
      (k) => `<tr><td class="mono">${esc(k.name)}</td><td class="mono" style="color:var(--dim)">${esc(k.subject ?? '')}</td>
      <td>${k.encrypted ? '<span class="pill ok">cifrada</span>' : '<span class="pill warn">en claro</span>'}</td>
      <td>${k.tlso ? (k.tlso.errors.length ? `<span class="pill bad">no cumple 5.7.1</span>` : '<span class="pill ok">TLSO valido</span>') : ''}</td></tr>`,
    )
    .join('');

  return layout({
    title: 'Claves',
    path: '/keys', flash,
    body: `<h1>Claves y certificados</h1>
    <p class="lead">El material privado se cifra en reposo. La consola nunca lo muestra ni lo exporta.</p>
    <table><tr><th>Nombre</th><th>Subject</th><th>Reposo</th><th>Perfil</th></tr>${rows}</table>

    <h2>Emitir</h2>
    <div class="card">
      <h3>Firmante de listas (TLSO)</h3>
      <div class="meta">Perfil de la clausula 5.7.1: CA=false, KeyUsage acotado,
      EKU id-tsl-kp-tslSigning y un subject cuyo C y O salen del esquema elegido.</div>
      <form class="inline" method="post" action="/keys/tlso">
        <input type="text" name="name" placeholder="nombre" required>
        <select name="scheme">${schemes.map((s) => `<option value="${esc(s.id)}">${esc(s.schemeName ?? s.id)}</option>`).join('')}</select>
        <button class="primary">Emitir TLSO</button>
      </form>
    </div>
    <div class="card">
      <h3>CA / hoja</h3>
      <div class="meta">Una CA raiz (IACA de emisor, CA de acceso) o una hoja firmada por ella.</div>
      <form class="inline" method="post" action="/keys/ca">
        <input type="text" name="name" placeholder="nombre" required>
        <input type="text" name="subject" placeholder="C=ES, O=..., CN=..." size="38" required>
        <select name="issuer"><option value="">— autofirmada (CA raiz) —</option>
          ${keys.map((k) => `<option>${esc(k.name)}</option>`).join('')}</select>
        <button class="primary">Emitir</button>
      </form>
    </div>`,
  });
}

export function docPage({ id, doc, problems, title, back, flash }) {
  return layout({
    title,
    path: back, flash,
    body: `<h1>${esc(title)}</h1>
    <p class="lead mono">${esc(id)}</p>
    ${
      problems?.length
        ? `<div class="flash bad">${esc(problems.join('\n'))}</div>`
        : '<div class="flash ok">El documento valida contra el modelo.</div>'
    }
    <form method="post" action="/docs/${encodeURIComponent(id)}">
      <textarea name="doc" spellcheck="false">${esc(JSON.stringify(doc, null, 2))}</textarea>
      <div style="margin-top:.6rem"><button class="primary">Guardar</button>
      <a href="${back}" style="margin-left:1rem">Volver</a></div>
    </form>
    <p class="note">El registro se edita como documento, no como formulario, a
    proposito: el modelo de TS5 tiene servicios, finalidades, credenciales y
    claims anidados, y un formulario de cuarenta campos seria mas lento de usar
    y mas facil de romper que el JSON con validacion al guardar.</p>`,
  });
}

export function rpPage({ rp, statusLists, signers, cas, flash }) {
  const services = rp.services
    .map(
      (s) => `<div class="card"><h3>${esc(s.name)} <span class="pill dim">${esc(s.id ?? 'sin id')}</span></h3>
      <form class="inline" method="post" action="/rps/${encodeURIComponent(rp.id)}/wrpac">
        <input type="hidden" name="service" value="${esc(s.id)}">
        <select name="ca">${cas.map((c) => `<option>${esc(c)}</option>`).join('')}</select>
        <button>Emitir access certificate</button>
      </form>
      <table style="margin-top:.7rem"><tr><th>Finalidad</th><th>Credenciales</th><th>Revocacion</th><th>WRPRC</th></tr>
      ${s.uses
        .map(
          (u) => `<tr><td>${esc(u.id)}<div class="meta">${esc(u.purpose ?? '')}</div></td>
          <td>${u.credentials}</td>
          <td class="mono">${u.statusIndex === undefined ? '<span class="pill warn">sin posicion</span>' : `#${u.statusIndex}`}</td>
          <td>${
            u.published ? '<span class="pill ok">emitido</span>' : '<span class="pill dim">no emitido</span>'
          }
          <form class="inline" method="post" action="/rps/${encodeURIComponent(rp.id)}/wrprc">
            <input type="hidden" name="service" value="${esc(s.id)}">
            <input type="hidden" name="use" value="${esc(u.id)}">
            <select name="signer">${signers.map((x) => `<option>${esc(x)}</option>`).join('')}</select>
            <button>Emitir</button></form></td></tr>`,
        )
        .join('')}</table></div>`,
    )
    .join('');

  return layout({
    title: rp.legalName ?? rp.id,
    path: '/rps', flash,
    body: `<h1>${esc(rp.legalName ?? rp.id)}</h1>
    <p class="lead">Un access certificate por servicio, un registration certificate por finalidad.</p>
    ${
      rp.problems.length
        ? `<div class="flash bad">${esc(rp.problems.join('\n'))}</div>`
        : '<div class="flash ok">El registro cumple el modelo de TS5/TS6.</div>'
    }
    ${services}
    <p><a href="/docs/${encodeURIComponent(rp.id)}">Editar el registro</a></p>`,
  });
}

export function statusPage({ lists, signers, flash }) {
  return layout({
    title: 'Revocacion',
    path: '/status', flash,
    body: `<h1>Revocacion</h1>
    <p class="lead">Cambiar una posicion no publica nada: hay que reemitir la lista para que el cambio salga.</p>
    ${lists
      .map(
        (l) => `<div class="card"><h3>${esc(l.id)} ${
          l.published ? `<span class="pill ok">publicada #${l.published.sequence}</span>` : '<span class="pill warn">sin publicar</span>'
        }</h3>
      <div class="meta mono">${esc(l.url ?? '')} · ${l.size} posiciones · ${l.revoked} no valida(s)</div>
      <table><tr><th>Posicion</th><th>Estado</th><th>Motivo</th><th></th></tr>
      ${Object.entries(l.entries)
        .map(
          ([idx, e]) => `<tr><td class="mono">${esc(idx)}</td>
          <td><span class="pill ${e.status === 'valid' ? 'ok' : 'bad'}">${esc(e.status)}</span></td>
          <td class="meta">${esc(e.note ?? '')}</td>
          <td><form class="inline" method="post" action="/status/${encodeURIComponent(l.id)}/set">
            <input type="hidden" name="idx" value="${esc(idx)}">
            <select name="status"><option>valid</option><option>invalid</option><option>suspended</option></select>
            <button>Cambiar</button></form></td></tr>`,
        )
        .join('')}
      <tr><td colspan="4"><form class="inline" method="post" action="/status/${encodeURIComponent(l.id)}/set">
        <input type="text" name="idx" placeholder="posicion" size="6" required>
        <select name="status"><option>invalid</option><option>suspended</option><option>valid</option></select>
        <input type="text" name="note" placeholder="motivo" size="30">
        <button>Anadir</button></form></td></tr></table>
      <form class="inline" method="post" action="/status/${encodeURIComponent(l.id)}/build">
        <select name="signer">${signers.map((s) => `<option>${esc(s)}</option>`).join('')}</select>
        <button class="primary">Reemitir lista</button></form>
      </div>`,
      )
      .join('')}`,
  });
}

export function listsPage({ items, flash }) {
  return layout({
    title: 'Listas',
    path: '/lists', flash,
    body: `<h1>Listas</h1>
    <p class="lead">El estado de cada lista es un documento. Editarlo no publica nada.</p>
    <table><tr><th>Lista</th><th>Tipo</th><th>Entradas</th><th>Publicada</th><th></th></tr>
    ${items
      .map(
        (i) => `<tr><td>${esc(i.title)}<div class="meta mono">${esc(i.id)}</div></td>
        <td class="meta">${esc(i.type)}</td><td>${i.entries}</td>
        <td>${i.published ? `#${i.published.sequence}` : '—'} ${badge(i)}</td>
        <td><a href="/docs/${encodeURIComponent(i.id)}">Editar</a></td></tr>`,
      )
      .join('')}</table>`,
  });
}
