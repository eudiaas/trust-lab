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
    button.danger { color:var(--bad); border-color:#da363355; background:#da36330f }
    .row { display:flex; gap:.4rem; flex-wrap:wrap; align-items:center }
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

/** Boton de borrado: confirma en el navegador y comprueba en el servidor. */
function delButton(action, label, aviso, extra = '') {
  return `<form class="inline" method="post" action="${action}"
    onsubmit="return confirm(${JSON.stringify(aviso)})">${extra}<button class="danger">${label}</button></form>`;
}

export function layout({ title, path, body, flash }) {
  const nav = [
    ['/', 'Estado'],
    ['/keys', 'Claves'],
    ['/lists', 'Listas'],
    ['/rps', 'Relying parties'],
    ['/status', 'Revocacion'],
    ['/graph', 'Dependencias'],
    ['/reset', 'Reiniciar'],
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
    <table><tr><th>Entidad</th><th>Registro</th><th>Servicios</th><th>Finalidades</th><th></th></tr>${rpRows}</table>`,
  });
}

// Los seis tipos de la tabla 2 de TS 119 475, con el prefijo semantico que
// cada uno produce en el certificado (EN 319 412-1 §5.1.3).
const ID_TYPE_LABELS = {
  'http://data.europa.eu/eudi/id/VATIN': 'NIF / VAT (VAT…)',
  'http://data.europa.eu/eudi/id/EUID': 'EUID registro mercantil (NTR…)',
  'http://data.europa.eu/eudi/id/LEI': 'LEI (LEI…)',
  'http://data.europa.eu/eudi/id/EORI-No': 'EORI (EOR…)',
  'http://data.europa.eu/eudi/id/TIN': 'TIN (VAT… / TIN…)',
  'http://data.europa.eu/eudi/id/Excise': 'Numero de impuestos especiales (EXC…)',
};

export function rpsPage({ rps, statusLists = [], flash }) {
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
        <td>${rp.services.reduce((n, s) => n + s.uses.length, 0)}</td>
        <td>${delButton(`/delete/rp/${encodeURIComponent(rp.id)}`, 'Borrar',
          `Borra el registro de ${rp.legalName ?? rp.id} junto con sus access certificates y sus WRPRC. Las posiciones de revocacion quedan libres.`)}</td></tr>`,
      )
      .join('')}</table>

    <h2>Dar de alta</h2>
    <div class="card">
      <div class="meta">Crea un esqueleto que <strong>ya valida</strong> contra TS5/TS6, con un
      servicio y una finalidad de ejemplo, y reserva una posicion libre en la lista de revocacion.
      Los campos que hay que rellenar despues van marcados como <span class="mono">PENDIENTE</span>.</div>
      <form method="post" action="/rps">
        <div class="row">
          <input type="text" name="id" placeholder="identificador (minusculas-y-guiones)"
                 pattern="[a-z0-9][a-z0-9-]*" required>
          <input type="text" name="legalName" placeholder="razon social" required>
        </div>
        <div class="row" style="margin-top:.5rem">
          <select name="identifierType">
            ${Object.entries(ID_TYPE_LABELS)
              .map(([uri, label]) => `<option value="${esc(uri)}">${esc(label)}</option>`)
              .join('')}
          </select>
          <input type="text" name="identifierValue" placeholder="valor (p. ej. B12345678)" required>
          <input type="text" name="country" placeholder="ES" size="3" pattern="[A-Za-z]{2}" value="ES" required>
          <select name="statusList">
            <option value="">sin lista de revocacion</option>
            ${statusLists.map((l) => `<option value="${esc(l.id)}">${esc(l.id)}</option>`).join('')}
          </select>
          <button class="primary">Crear</button>
        </div>
      </form>
    </div>`,
  });
}

export function keysPage({ keys, cas = [], roles = {}, schemes, flash }) {
  const ROLE_PILL = {
    CA: 'dim', 'firmante de listas': 'ok', 'access certificate': 'ok',
    hoja: 'dim', 'sin certificado': 'bad', ilegible: 'bad',
  };
  const rows = keys
    .map(
      (k) => `<tr><td class="mono">${esc(k.name)}</td>
      <td><span class="pill ${ROLE_PILL[k.role] ?? 'dim'}">${esc(k.role ?? '')}</span>${
        k.policy ? ` <span class="meta mono">${esc(k.policy)}</span>` : ''
      }${k.selfSigned ? ' <span class="meta">autofirmado</span>' : ''}</td>
      <td class="mono" style="color:var(--dim)">${esc(k.subject ?? '')}</td>
      <td>${k.encrypted ? '<span class="pill ok">cifrada</span>' : '<span class="pill warn">en claro</span>'}</td>
      <td>${
        k.expired
          ? `<span class="pill bad">caducado ${esc(k.notAfter ?? '')}</span>`
          : `<span class="meta mono">${esc(k.notAfter ?? '')}</span>`
      }${
        k.tlso
          ? k.tlso.errors.length
            ? ' <span class="pill bad">no cumple 5.7.1</span>'
            : ' <span class="pill ok">5.7.1</span>'
          : ''
      }</td>
      <td class="meta">${keyLinks(k.name)}
      ${delButton(`/delete/key/${encodeURIComponent(k.name)}`, 'Borrar',
        `Borra la clave ${k.name} y su certificado. Si algo depende de ella, la operacion se rechaza y te dice que.`)}</td></tr>`,
    )
    .join('');

  return layout({
    title: 'Claves',
    path: '/keys', flash,
    body: `<h1>Claves y certificados</h1>
    <p class="lead">El material privado se cifra en reposo y nunca se muestra en pantalla, pero
    <strong>si se puede descargar</strong> desde aqui: un access certificate que no sale de la fabrica
    no le sirve a nadie. Las descargas marcadas con 🔑 contienen la clave privada y quedan registradas
    en el log del servicio. El publisher no tiene ninguna de estas rutas.</p>
    <table><tr><th>Nombre</th><th>Que es</th><th>Subject</th><th>Reposo</th><th>Caduca</th><th>Descargar</th></tr>${rows}</table>
    <p class="note">Cada fila es un <strong>par clave + certificado</strong> bajo un nombre: el
    almacen no guarda certificados por un lado y claves por otro. Lo que la fila <em>es</em>
    —CA, firmante de listas, access certificate o una hoja cualquiera— no lo dice el nombre, que
    lo pone quien la emite, sino las extensiones del certificado: BasicConstraints para la CA,
    el EKU <span class="mono">id-tsl-kp-tslSigning</span> para el firmante y el OID de politica
    de TS 119 411-8 para el access certificate.</p>

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
      <h3>Firmante de credenciales o atestaciones</h3>
      <div class="meta">El Document Signer del PID, el que firma los registration certificates
      y los de Wallet Instance Attestation / Key Attestation. Siempre cuelga de una CA: lo que
      hace util a este certificado no es su perfil, es que <strong>su ancla sea la que publica
      la lista</strong> correspondiente.</div>
      <form method="post" action="/keys/signer">
        <div class="row">
          <input type="text" name="name" placeholder="nombre" required>
          <select name="role">
            ${Object.entries(roles)
              .map(([id, r]) => `<option value="${esc(id)}">${esc(r.label)} → ${esc(r.lista)}</option>`)
              .join('')}
          </select>
          <select name="issuer">${cas.map((c) => `<option>${esc(c)}</option>`).join('')}</select>
        </div>
        <div class="row" style="margin-top:.5rem">
          <input type="text" name="subject" placeholder="C=ES, O=Lab PID Provider, CN=Lab PID DS 01"
                 size="52" required>
          <button class="primary">Emitir firmante</button>
        </div>
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

/**
 * Enlaces de descarga de una clave. La cadena va primero y sin aviso porque no
 * es secreta —es lo que se pinea en el otro extremo—; las otras tres llevan la
 * privada dentro y se marcan como tal.
 */
function keyLinks(name) {
  const n = encodeURIComponent(name);
  return [
    `<a href="/download/key/${n}?form=chain">cadena .crt</a>`,
    `<a href="/download/key/${n}?form=bundle" title="clave privada + cadena">bundle .pem 🔑</a>`,
    `<a href="/download/key/${n}?form=key" title="solo la clave privada">clave .pem 🔑</a>`,
    `<a href="/download/key/${n}?form=jwk" title="JWK privada con x5c">jwk 🔑</a>`,
  ].join(' · ');
}

export function rpPage({ rp, statusLists, signers, cas, flash }) {
  const services = rp.services
    .map(
      (s) => `<div class="card"><h3>${esc(s.name)} <span class="pill dim">${esc(s.id ?? 'sin id')}</span></h3>
      <form class="inline" method="post" action="/rps/${encodeURIComponent(rp.id)}/wrpac">
        <input type="hidden" name="service" value="${esc(s.id)}">
        <select name="ca">${cas.map((c) => `<option>${esc(c)}</option>`).join('')}</select>
        <button>${s.accessKey ? 'Reemitir' : 'Emitir'} access certificate</button>
      </form>
      ${
        s.accessKey
          ? `<div class="meta" style="margin-top:.4rem">Access certificate <span class="mono">${esc(s.accessKey)}</span> ·
             ${keyLinks(s.accessKey)}</div>`
          : ''
      }
      <table style="margin-top:.7rem"><tr><th>Finalidad</th><th>Credenciales</th><th>Revocacion</th><th>WRPRC</th></tr>
      ${s.uses
        .map(
          (u) => `<tr><td>${esc(u.id)}<div class="meta">${esc(u.purpose ?? '')}</div></td>
          <td>${u.credentials}</td>
          <td class="mono">${u.statusIndex === undefined ? '<span class="pill warn">sin posicion</span>' : `#${u.statusIndex}`}</td>
          <td>${
            u.published
              ? `<span class="pill ok">emitido</span> <a href="/download/wrprc/${encodeURIComponent(
                  u.artifactId,
                )}">descargar .jwt</a>
                ${delButton(`/delete/wrprc/${encodeURIComponent(u.artifactId)}`, 'Borrar',
                  `Borra el WRPRC ${u.artifactId}. El registro y su posicion de revocacion se quedan, asi que se puede reemitir.`,
                  `<input type="hidden" name="rp" value="${esc(rp.id)}">`)}`
              : '<span class="pill dim">no emitido</span>'
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
        (i) => `<tr><td><a href="/lists/${encodeURIComponent(i.id)}">${esc(i.title)}</a>
        <div class="meta mono">${esc(i.id)}</div></td>
        <td class="meta">${esc(i.type)}</td><td>${i.entries}</td>
        <td>${i.published ? `#${i.published.sequence}` : '—'} ${badge(i)}</td>
        <td><a href="/lists/${encodeURIComponent(i.id)}">Contenido</a>
        <a href="/docs/${encodeURIComponent(i.id)}" style="margin-left:.6rem">JSON</a>
        ${
          i.published
            ? delButton(`/delete/unpublish/${encodeURIComponent(i.id)}`, 'Retirar',
                `Retira la version publicada de ${i.id}. ${i.url ?? ''} deja de servirse hasta que se reemita. El documento no se toca.`)
            : ''
        }</td></tr>`,
      )
      .join('')}</table>`,
  });
}


/**
 * El grafo dibujado, con la lista de cadenas rotas debajo.
 *
 * El dibujo responde a la pregunta «como esta montado esto»; la lista, a «que
 * esta mal». Las dos salen del MISMO grafo que consulta el borrado, asi que no
 * pueden discrepar.
 */
export function graphPage({ svg, graph, dangling, flash }) {
  const cols = ['firma las listas', 'listas', 'anclas publicadas', 'lo que cuelga de ellas', 'emitido'];
  return layout({
    title: 'Dependencias',
    path: '/graph', flash,
    body: `<h1>Dependencias criptograficas</h1>
    <p class="lead">De izquierda a derecha va la direccion de la confianza: quien firma
    → la lista → lo que la lista publica como ancla → lo que cuelga de ello → lo emitido.
    Un artefacto vale si su cadena termina en un ancla publicada; nada mas.</p>
    <div class="meta">${cols.map((c, i) => `<b>${i + 1}.</b> ${esc(c)}`).join(' · ')}</div>
    ${
      dangling.length
        ? `<div class="flash bad">${esc(
            `${dangling.length} cadena(s) no llegan a ningun ancla:\n` +
              dangling.map((d) => `· ${d.label}: ${d.why}`).join('\n'),
          )}</div>`
        : '<div class="flash ok">Todas las cadenas terminan en un ancla publicada.</div>'
    }
    <div class="card" style="overflow-x:auto">${svg}</div>
    <p class="note">En rojo, lo que no encadena con nada: incluye las <strong>anclas
    huerfanas</strong> —certificados publicados en una lista cuya clave privada no esta en
    este almacen, que es como vienen sembradas las listas— y cualquier certificado emitido
    bajo una CA que ninguna lista publica. Los dos casos producen artefactos que firman
    bien y que una wallet rechaza.</p>
    <p class="meta">${graph.nodes.length} nodos · ${graph.edges.length} aristas ·
    <a href="/graph.svg">descargar SVG</a></p>`,
  });
}

/**
 * Reinicio. Dos alcances, y la diferencia entre ellos es toda la pagina.
 *
 * El inventario va ANTES del formulario a proposito: «vas a perder 7 claves»
 * no ayuda a decidir; ver que una de ellas es la que firma las cinco listas,
 * si. La frase escrita a mano no es teatro — es lo unico que distingue este
 * boton de un clic accidental, porque aqui no hay papelera.
 */
export function resetPage({ preview, flash }) {
  const total = preview.publicado.length + preview.wrprc.length;
  const lista = (items) =>
    items.length
      ? `<ul class="blockers">${items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>`
      : '<div class="meta">nada</div>';

  return layout({
    title: 'Reiniciar',
    path: '/reset', flash,
    body: `<h1>Reiniciar el laboratorio</h1>
    <p class="lead">Dos alcances. El primero es reversible y casi siempre es el que hace falta;
    el segundo no lo es.</p>

    <div class="card">
      <h3>Inventario actual</h3>
      <div class="meta">Esto es lo que hay ahora mismo en el almacen.</div>
      <p class="meta"><b>Publicado (${total})</b></p>
      ${lista([
        ...preview.publicado.map((a) => `${a.id} #${a.sequence}${a.url ? ` — ${a.url}` : ''}`),
        ...preview.wrprc.map((id) => `WRPRC ${id}`),
      ])}
      <p class="meta"><b>Claves (${preview.keys.length})</b> — se pierden con «borrar todo»,
      y no hay copia en ningun otro sitio</p>
      ${lista(preview.keys.map((k) => `${k.name}${k.subject ? ` — ${k.subject}` : ''}`))}
      <p class="meta"><b>Documentos (${preview.docs.length})</b></p>
      ${lista(preview.docs.map((d) => `${d.id}${d.esRp ? ' (relying party)' : ''}`))}
    </div>

    <div class="card">
      <h3>Retirar lo publicado</h3>
      <div class="meta">Borra los ${total} artefacto(s) emitidos. <strong>Conserva claves y
      documentos</strong>, asi que se puede corregir lo que estuviera mal y reemitir sin volver
      a montar nada. El publisher devolvera 404 hasta que reemitas.</div>
      <form class="inline" method="post" action="/reset">
        <input type="hidden" name="scope" value="publicado">
        <input type="text" name="confirm" placeholder="escribe RETIRAR" size="22" required
               autocomplete="off" spellcheck="false">
        <button class="danger">Retirar lo publicado</button>
      </form>
    </div>

    <div class="card" style="border-color:var(--bad)">
      <h3>Borrar todo</h3>
      <div class="meta"><strong>Irreversible.</strong> Borra artefactos, las
      ${preview.keys.length} clave(s) y los ${preview.docs.length} documento(s), y vuelve a sembrar
      <span class="mono">state/</span>. Las claves privadas estan cifradas en este almacen y en
      ningun otro sitio: lo que ya hayas entregado a alguien deja de poder reemitirse igual.
      Ademas, el sembrado devuelve las <strong>anclas de ejemplo sin clave privada</strong>, que
      hay que volver a quitar.</div>
      <form class="inline" method="post" action="/reset"
        onsubmit="return confirm('Se borran las claves privadas. No hay copia. ¿Seguro?')">
        <input type="hidden" name="scope" value="todo">
        <input type="text" name="confirm" placeholder="escribe BORRAR TODO" size="22" required
               autocomplete="off" spellcheck="false">
        <button class="danger">Borrar todo</button>
      </form>
    </div>`,
  });
}

/**
 * Que contiene una lista. Es la pagina que faltaba.
 *
 * Antes se poblaba una lista anadiendo de uno en uno y se vaciaba editando el
 * JSON, asi que en la practica las listas acumulaban lo sembrado sin que nadie
 * lo mirara. Aqui la pregunta es la correcta —QUE contiene esta lista— y se
 * responde de una vez, marcando sobre lo que hay en el almacen.
 */
export function listMembersPage({ item, doc, esAv, candidatos, huerfanos, keys, flash }) {
  const row = (c) => {
    const check = `<input type="checkbox" name="sel" value="key:${esc(c.keyName)}"
      id="c-${esc(c.keyName)}" ${c.dentro ? 'checked' : ''}>`;
    const cc = esAv
      ? `<input type="text" name="cc:${esc(c.keyName)}" value="${esc(c.cc ?? 'ES')}" size="2"
           maxlength="2" title="Estado miembro que notifica al PAAP" style="width:3.2rem">`
      : `<select name="rev:${esc(c.keyName)}" title="clave del servicio de revocacion (opcional)">
           <option value="">sin revocacion</option>
           ${keys.filter((k) => k !== c.keyName).map((k) => `<option>${esc(k)}</option>`).join('')}
         </select>`;
    return `<tr>
      <td>${check}</td>
      <td><label for="c-${esc(c.keyName)}" class="mono">${esc(c.keyName)}</label>
        <div class="meta">${esc(c.role ?? '')}${c.expired ? ' · <b>caducado</b>' : ''}${
          c.tambien?.length ? ` · ancla de ${esc(c.tambien.join(', '))}` : ''
        }</div></td>
      <td class="meta mono" style="max-width:24rem">${esc(c.subject ?? '')}</td>
      <td><input type="text" name="name:${esc(c.keyName)}" value="${esc(c.displayName ?? '')}"
        placeholder="nombre publicado" size="26"></td>
      <td>${cc}</td>
    </tr>`;
  };

  const huerfanoRows = huerfanos
    .map(
      (h) => `<tr>
      <td><input type="checkbox" name="sel" value="orphan:${esc(h.fingerprint)}"
        id="o-${esc(h.fingerprint)}" checked></td>
      <td><label for="o-${esc(h.fingerprint)}">${esc(h.displayName ?? '')}</label>
        <div class="meta"><span class="pill bad">sin clave privada</span></div></td>
      <td class="meta mono">${esc(h.fingerprint.slice(0, 24))}…</td>
      <td class="meta" colspan="2">No se puede emitir nada con esto. Desmarcalo para quitarlo.</td>
    </tr>`,
    )
    .join('');

  return layout({
    title: item?.title ?? doc.id,
    path: '/lists', flash,
    body: `<h1>${esc(item?.title ?? doc.id)}</h1>
    <p class="lead">${esc(item?.type ?? doc.kind)} · <span class="mono">${esc(doc.url ?? '')}</span></p>

    ${
      huerfanos.length
        ? `<div class="flash bad">${esc(
            `${huerfanos.length} entrada(s) publicadas sin clave privada en este almacen. ` +
              'La lista dice "confia en esto" y nadie puede emitir con ello: es lo que viene sembrado de fabrica. ' +
              'Desmarcalas y guarda.',
          )}</div>`
        : ''
    }

    <form method="post" action="/lists/${encodeURIComponent(doc.id)}/providers">
      <div class="card">
        <h3>Que contiene esta lista</h3>
        <div class="meta">Marca lo que debe publicar. ${
          esAv
            ? 'Una AV Trusted List publica el <strong>Document Signer</strong>, no la IACA, y cada entrada necesita el Estado miembro que la notifica.'
            : 'Una LoTE publica el <strong>ancla de la cadena</strong>: da igual que marques la CA o una hoja que cuelgue de ella, se guarda la raiz.'
        }</div>
        <table><tr><th></th><th>Clave</th><th>Subject</th><th>Nombre publicado</th>
          <th>${esAv ? 'EM' : 'Revocacion'}</th></tr>
          ${huerfanoRows}${candidatos.map(row).join('')}
        </table>
        <div style="margin-top:.8rem"><button class="primary">Guardar seleccion</button>
        <span class="meta" style="margin-left:.8rem">Guardar no publica: hay que reemitir.</span></div>
      </div>
    </form>

    <div class="card">
      <h3>Publicar</h3>
      <div class="meta">${
        item?.blockers?.length
          ? 'No se puede emitir todavia:'
          : item?.published
            ? `Publicada #${item.published.sequence}. Reemite para que salga lo que acabas de guardar.`
            : 'Sin publicar.'
      }</div>
      ${
        item?.blockers?.length
          ? `<ul class="blockers">${item.blockers.map((b) => `<li>${esc(b)}</li>`).join('')}</ul>`
          : `<form class="inline" method="post" action="/lists/${encodeURIComponent(doc.id)}/build">
               <select name="signer">${(item?.signers ?? []).map((x) => `<option>${esc(x)}</option>`).join('')}</select>
               <button class="primary">Emitir y publicar</button></form>`
      }
    </div>
    <p><a href="/docs/${encodeURIComponent(doc.id)}">Editar el documento entero</a> ·
    <a href="/lists">Volver</a></p>`,
  });
}
