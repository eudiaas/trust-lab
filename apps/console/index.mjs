#!/usr/bin/env node
// La consola de operacion. Es la superficie de ESCRITURA: crea CAs, firma
// listas y emite certificados, asi que va detras de login y en su propio
// servicio — nunca en el mismo proceso que el publisher, que es el que da la
// cara a internet y que a proposito no puede descifrar ninguna clave.
//
// Sin framework y sin build. Son ocho pantallas de operador; un paso de
// compilacion aqui compraria muy poco a cambio de otra cosa que puede romper
// el despliegue.
import 'reflect-metadata';
import { createServer } from 'node:http';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { dirname, join } from 'node:path';
import { Crypto } from '@peculiar/webcrypto';
import { cryptoProvider } from '@peculiar/x509';
import { openStore, seedIfEmpty } from '../../packages/store/src/index.mjs';
import * as ops from '../../packages/ops/src/index.mjs';
import { assertRegistry } from '../../packages/registry/src/index.mjs';
import { describeKey, assertTlsoProfile, SIGNER_ROLES, signerRole } from '../../packages/ca/src/index.mjs';
import { readiness, rpReadiness, tlsoCandidates, signingCandidates } from './readiness.mjs';
import * as views from './views.mjs';
import { buildGraph, danglingChains } from '../../packages/graph/src/index.mjs';
import { graphSvg } from './graph-svg.mjs';

const crypto = new Crypto();
cryptoProvider.set(crypto);
const ROOT = join(dirname(new URL(import.meta.url).pathname), '../..');
const PORT = Number(process.env.PORT ?? 8081);

// Fail-closed: una consola que emite certificados no arranca sin contrasena.
// El precedente de la casa es el mismo: sin secreto, el guard no degrada, falla.
const PASSWORD = process.env.CONSOLE_PASSWORD;
if (!PASSWORD) {
  console.error(
    'error: falta CONSOLE_PASSWORD. Esta consola crea CAs y emite certificados; ' +
      'no se arranca sin autenticacion.',
  );
  process.exit(1);
}
// El secreto de sesion es efimero por defecto: al reiniciar, las sesiones
// caducan. Para una consola de laboratorio es lo correcto.
const SECRET = process.env.CONSOLE_SECRET ?? randomBytes(32).toString('hex');
const TTL_MS = 12 * 3600 * 1000;

const sign = (value) => createHmac('sha256', SECRET).update(value).digest('base64url');

function issueCookie() {
  const exp = String(Date.now() + TTL_MS);
  return `tl=${exp}.${sign(exp)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${TTL_MS / 1000}`;
}

function authenticated(req) {
  const raw = /tl=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
  if (!raw) return false;
  const [exp, mac] = raw.split('.');
  if (!exp || !mac || Number(exp) < Date.now()) return false;
  const expected = Buffer.from(sign(exp));
  const got = Buffer.from(mac);
  return expected.length === got.length && timingSafeEqual(expected, got);
}

// Un fallo de configuracion —falta la base de datos, falta la clave— es un
// mensaje que el operador tiene que poder leer en los logs de Railway, no una
// pila de llamadas.
const store = await openStore({ root: ROOT }).catch((err) => {
  console.error(`error: ${err.message}`);
  process.exit(1);
});

async function body(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
}

const send = (res, status, payload, headers = {}) => {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex', ...headers });
  res.end(payload);
};
const redirect = (res, to, flash) =>
  send(res, 303, '', { Location: flash ? `${to}?${new URLSearchParams(flash)}` : to });

/** Envuelve una operacion: exito y error acaban los dos en un mensaje, no en una pila. */
async function run(res, back, fn, okMessage) {
  try {
    const r = await fn();
    redirect(res, back, { ok: typeof okMessage === 'function' ? okMessage(r) : okMessage });
  } catch (err) {
    const detail = [err.message, ...(err.details ?? []).map((d) => '· ' + d)].join('\n');
    redirect(res, back, { bad: detail });
  }
}

const flashOf = (url) => {
  const ok = url.searchParams.get('ok');
  const bad = url.searchParams.get('bad');
  return ok ? { type: 'ok', message: ok } : bad ? { type: 'bad', message: bad } : null;
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
    const path = url.pathname;

    if (path === '/health') return send(res, 200, 'ok', { 'Content-Type': 'text/plain' });

    if (path === '/login' && req.method === 'POST') {
      const form = await body(req);
      const given = Buffer.from(form.get('password') ?? '');
      const want = Buffer.from(PASSWORD);
      const ok = given.length === want.length && timingSafeEqual(given, want);
      if (!ok) return send(res, 401, views.loginPage({ error: 'Contrasena incorrecta.' }));
      return send(res, 303, '', { Location: '/', 'Set-Cookie': issueCookie() });
    }

    if (!authenticated(req)) return send(res, 401, views.loginPage({}));

    const flash = flashOf(url);
    const parts = path.split('/').filter(Boolean);

    // ---- lectura ----
    if (path === '/' && req.method === 'GET') {
      const [items, rps, signers] = await Promise.all([
        readiness(store), rpReadiness(store), tlsoCandidates(store, null),
      ]);
      return send(res, 200, views.dashboard({
        items, rps, signers: signers.filter((s) => !s.errors.length), flash,
      }));
    }

    if (path === '/lists' && req.method === 'GET') {
      return send(res, 200, views.listsPage({ items: await readiness(store), flash }));
    }

    if (path === '/keys' && req.method === 'GET') {
      // El listado NO descifra nada: lee por `rawKeys` y solo mira si el
      // material esta envuelto. Ver el inventario no deberia exigir tocarlo.
      const raw = store.rawKeys ?? store.keys;
      const keys = [];
      for (const name of await store.keys.list()) {
        const doc = await raw.get(name);
        // El certificado se lee SIN descifrar la privada: el material publico
        // se guarda en claro justamente para esto.
        const cert = doc?.crt?.[0];
        keys.push({
          name, subject: doc?.subject, encrypted: !!doc?.keyEnc,
          ...(cert ? describeKey(cert) : { role: 'sin certificado' }),
          // El veredicto 5.7.1 solo es una respuesta util para un firmante:
          // decir que un access certificate "no cumple 5.7.1" seria ruido, no
          // un hallazgo — no pretende cumplirlo.
          tlso: cert && describeKey(cert).role === 'firmante de listas'
            ? assertTlsoProfile(cert, {}, { checkNaming: false })
            : null,
        });
      }
      const schemes = (await store.docs.list('*')).filter((d) => d.kind === 'etsi-tl-xml');
      const cas = keys.filter((k) => k.ca).map((k) => k.name);
      const roles = Object.fromEntries(Object.keys(SIGNER_ROLES).map((k) => [k, signerRole(k)]));
      return send(res, 200, views.keysPage({ keys, cas, roles, schemes, flash }));
    }

    if (path === '/rps' && req.method === 'GET') {
      const statusLists = (await store.docs.list('*')).filter((d) => d.kind === 'token-status-list');
      return send(res, 200, views.rpsPage({ rps: await rpReadiness(store), statusLists, flash }));
    }

    if (parts[0] === 'rps' && parts.length === 2 && req.method === 'GET') {
      const rps = await rpReadiness(store);
      const rp = rps.find((r) => r.id === parts[1]);
      if (!rp) return send(res, 404, 'no existe');
      // Firmar un WRPRC no es firmar una lista: no se pide el perfil 5.7.1.
      const signers = (await signingCandidates(store))
        .filter((s) => !s.expired)
        .map((s) => s.name);
      const cas = await store.keys.list();
      return send(res, 200, views.rpPage({ rp, statusLists: [], signers, cas, flash }));
    }

    if (path === '/status' && req.method === 'GET') {
      const docs = (await store.docs.list('*')).filter((d) => d.kind === 'token-status-list');
      const lists = [];
      for (const d of docs) {
        lists.push({
          id: d.id, url: d.url, size: d.size, entries: d.entries ?? {},
          revoked: Object.values(d.entries ?? {}).filter((e) => e.status !== 'valid').length,
          published: await store.artifacts.latest('status', d.id),
        });
      }
      const signers = (await tlsoCandidates(store, null)).filter((s) => !s.errors.length).map((s) => s.name);
      return send(res, 200, views.statusPage({ lists, signers, flash }));
    }

    // ---- descarga ----
    // Detras del login, y con `attachment` para que el navegador no pinte una
    // clave privada en una pestana. El publisher NO tiene ninguna de estas
    // rutas: no puede descifrar claves y no debe servir WRPRC, que no es
    // material publicado sino material que se entrega a su titular.
    if (parts[0] === 'lists' && parts.length === 2 && req.method === 'GET') {
      const doc = await store.docs.get('*', parts[1]);
      if (!doc) return send(res, 404, 'no existe');
      const item = (await readiness(store)).find((i) => i.id === parts[1]);
      return send(res, 200, views.listMembersPage({
        id: parts[1], item, doc, ...(await ops.listCandidates(store, parts[1])),
        keys: await store.keys.list(), flash,
      }));
    }

    if (path === '/graph.svg' && req.method === 'GET') {
      const g = await buildGraph(store);
      return send(res, 200, graphSvg(g, { dangling: danglingChains(g) }), {
        'Content-Type': 'image/svg+xml',
        'Content-Disposition': 'attachment; filename="trust-lab-dependencias.svg"',
      });
    }

    if (path === '/graph' && req.method === 'GET') {
      const g = await buildGraph(store);
      const roto = danglingChains(g);
      return send(res, 200, views.graphPage({ svg: graphSvg(g, { dangling: roto }), graph: g, dangling: roto, flash }));
    }

    if (path === '/reset' && req.method === 'GET') {
      return send(res, 200, views.resetPage({ preview: await ops.resetPreview(store), flash }));
    }

    if (parts[0] === 'download' && req.method === 'GET') {
      let out;
      try {
        if (parts[1] === 'key' && parts.length === 3) {
          out = await ops.exportKey(store, crypto, {
            name: decodeURIComponent(parts[2]),
            form: url.searchParams.get('form') ?? 'chain',
          });
          if (out.secret) {
            console.warn(`[export] clave privada "${parts[2]}" descargada (${out.filename})`);
          }
        } else if (parts.length === 3) {
          out = await ops.exportArtifact(store, {
            kind: parts[1], id: decodeURIComponent(parts[2]), sequence: url.searchParams.get('n'),
          });
        } else {
          return send(res, 404, 'no existe');
        }
      } catch (err) {
        return send(res, 404, `<pre>${err.message}</pre>`);
      }
      return send(res, 200, out.body, {
        'Content-Type': out.contentType,
        'Content-Disposition': `attachment; filename="${out.filename}"`,
        'Cache-Control': 'no-store',
      });
    }

    if (parts[0] === 'docs' && parts.length === 2 && req.method === 'GET') {
      const doc = await store.docs.get('*', parts[1]);
      if (!doc) return send(res, 404, 'no existe');
      const problems = doc.walletRelyingParty ? assertRegistry(doc) : [];
      return send(res, 200, views.docPage({
        id: parts[1], doc, problems, flash,
        title: doc.schemeName ?? doc.walletRelyingParty?.legalName ?? parts[1],
        back: doc.walletRelyingParty ? '/rps' : '/lists',
      }));
    }

    // ---- escritura ----
    if (req.method !== 'POST') return send(res, 404, 'no existe');

    const form = await body(req);

    if (path === '/keys/tlso') {
      return run(res, '/keys', () =>
        ops.mintTlso(store, crypto, { name: form.get('name'), schemeId: form.get('scheme') }),
        (r) => `Firmante ${r.name} emitido: ${r.subject}`);
    }

    if (path === '/reset') {
      return run(res, '/reset', () =>
        ops.reset(store, { scope: form.get('scope'), confirm: form.get('confirm'), root: ROOT }),
        (r) =>
          r.scope === 'publicado'
            ? `Retirados ${r.retirados} artefacto(s). Las claves y los documentos siguen ahi: reemite cuando este corregido.`
            : `Borrado todo: ${r.retirados} artefacto(s), ${r.claves} clave(s), ${r.documentos} documento(s).` +
              (r.sembrados.length ? ` Resembrados ${r.sembrados.length} documento(s) desde state/.` : ''));
    }

    // ---- borrado ----
    // El aviso lo da la operacion, que consulta el grafo. La confirmacion del
    // navegador es cortesia; la comprobacion de verdad es server-side.
    if (parts[0] === 'delete' && parts.length === 3) {
      const force = form.get('force') === '1';
      const [, tipo, id] = parts;
      const back = { key: '/keys', rp: '/rps', wrprc: `/rps/${form.get('rp') ?? ''}`, list: '/lists' }[tipo] ?? '/';
      if (tipo === 'key') {
        return run(res, back, () => ops.deleteKey(store, { name: decodeURIComponent(id), force }),
          (r) => `Borrada ${r.deleted}.` + (r.broke.length ? ` Rotas ${r.broke.length} cadena(s).` : ''));
      }
      if (tipo === 'rp') {
        return run(res, '/rps', () => ops.deleteRp(store, { id: decodeURIComponent(id), force }),
          (r) => `Borrado ${r.deleted}` + (r.retirados.length ? ` y ${r.retirados.length} artefacto(s) suyos.` : '.'));
      }
      if (tipo === 'wrprc') {
        return run(res, back, () => ops.deleteWrprc(store, { id: decodeURIComponent(id) }),
          (r) => `Borrado el WRPRC ${r.deleted}. El registro y su posicion de revocacion se quedan.`);
      }
      if (tipo === 'unpublish') {
        return run(res, '/lists', () => ops.unpublish(store, { id: decodeURIComponent(id) }),
          (r) => `Retirada la version #${r.retirada} de ${r.id}: ${r.url} deja de servirse hasta reemitir.`);
      }
      return send(res, 404, 'no existe');
    }

    if (parts[0] === 'lists' && parts[2] === 'providers') {
      const id = decodeURIComponent(parts[1]);
      // Las filas llegan como `sel` (una por elegida) y campos indexados por
      // ella: es la unica forma de que el orden del formulario no importe.
      const seleccion = form.getAll('sel').map((ref) => {
        const [tipo, valor] = [ref.slice(0, ref.indexOf(':')), ref.slice(ref.indexOf(':') + 1)];
        return tipo === 'orphan'
          ? { fingerprint: valor }
          : {
              keyName: valor,
              displayName: form.get(`name:${valor}`),
              cc: form.get(`cc:${valor}`),
              revocationKeyName: form.get(`rev:${valor}`) || undefined,
            };
      });
      return run(res, `/lists/${encodeURIComponent(id)}`, () => ops.setProviders(store, { id, seleccion }),
        (r) => `${r.id}: ${r.entradas} entrada(s)` +
          (r.quitadas > 0 ? `, ${r.quitadas} quitada(s)` : '') +
          '. No publica: reemite la lista para que salga.');
    }

    if (parts[0] === 'lists' && parts[2] === 'remove-provider') {
      return run(res, '/lists', () => ops.removeProvider(store, { id: parts[1], ref: form.get('ref') }),
        (r) => `Quitado "${r.removed}" de ${r.id}. No publica: hay que reemitir la lista.`);
    }

    if (path === '/keys/signer') {
      return run(res, '/keys', () =>
        ops.mintSigner(store, crypto, {
          name: form.get('name')?.trim(), issuer: form.get('issuer') || undefined,
          role: form.get('role'), subject: form.get('subject')?.trim(),
        }),
        (r) => r.selfSigned
          ? `${r.spec.label} ${r.name} emitido autofirmado. Publica este mismo certificado en ${r.spec.lista}.`
          : `${r.spec.label} ${r.name} emitido bajo ${r.issuer}. Publica ese ancla en ${r.spec.lista}.`);
    }

    if (path === '/keys/ca') {
      return run(res, '/keys', () =>
        ops.mintKey(store, crypto, {
          name: form.get('name'), subject: form.get('subject'), issuer: form.get('issuer') || undefined,
        }),
        (r) => `${r.name} emitida: ${r.subject}`);
    }

    if (parts[0] === 'lists' && parts[2] === 'build') {
      const doc = await store.docs.get('*', parts[1]);
      const fn = doc?.kind === 'etsi-tl-xml' ? ops.buildAvList : ops.buildLoteList;
      return run(res, '/', () => fn(store, crypto, { id: parts[1], signerName: form.get('signer') }),
        (r) => `Lista ${r.id} emitida (#${r.sequence}). Publicada en ${r.url}` +
          (r.warnings?.length ? `\n⚠ ${r.warnings.join('\n⚠ ')}` : ''));
    }

    if (parts[0] === 'status' && parts[2] === 'set') {
      return run(res, '/status', () =>
        ops.setStatus(store, {
          id: parts[1], idx: form.get('idx'), status: form.get('status'), note: form.get('note'),
        }),
        (r) => `Posicion ${r.idx} → ${r.status}. Pendiente de reemitir la lista para que se publique.`);
    }

    if (parts[0] === 'status' && parts[2] === 'build') {
      return run(res, '/status', () =>
        ops.buildStatusList(store, crypto, { id: parts[1], signerName: form.get('signer') }),
        (r) => `Status list ${r.id} reemitida (#${r.sequence}) · ${r.revoked} no valida(s)`);
    }

    if (path === '/rps' && parts.length === 1) {
      return run(res, '/rps', () =>
        ops.createRp(store, {
          id: form.get('id')?.trim(),
          legalName: form.get('legalName')?.trim(),
          country: form.get('country')?.trim().toUpperCase(),
          identifierType: form.get('identifierType'),
          identifierValue: form.get('identifierValue')?.trim(),
          statusListId: form.get('statusList') || undefined,
        }),
        (r) =>
          `Alta de ${r.legalName}: esqueleto valido creado` +
          (r.statusList ? `, posicion ${Object.values(r.statusList.indexByIntendedUse)[0]} reservada` : '') +
          '. Editalo para rellenar los campos PENDIENTE.');
    }

    if (parts[0] === 'rps' && parts[2] === 'wrpac') {
      return run(res, `/rps/${parts[1]}`, () =>
        ops.issueWrpac(store, crypto, {
          registryId: parts[1], serviceId: form.get('service'), caName: form.get('ca'),
        }),
        (r) => `Access certificate ${r.name} emitido bajo ${r.policy}`);
    }

    if (parts[0] === 'rps' && parts[2] === 'wrprc') {
      return run(res, `/rps/${parts[1]}`, () =>
        ops.issueWrprc(store, crypto, {
          registryId: parts[1], serviceId: form.get('service'),
          useId: form.get('use'), signerName: form.get('signer'),
        }),
        (r) => `WRPRC ${r.id} emitido (edicion ${r.edition})`);
    }

    if (parts[0] === 'docs' && parts.length === 2) {
      return run(res, `/docs/${parts[1]}`, async () => {
        const doc = JSON.parse(form.get('doc'));
        if (doc.walletRelyingParty) {
          const problems = assertRegistry(doc);
          if (problems.length) throw new ops.OpError('el registro no cumple TS5/TS6', problems);
        }
        // Borrar antes de escribir: si la edicion cambia el `kind`, en SQL
        // —clave primaria (kind, id)— un put a secas dejaria la fila vieja
        // ahi, con el mismo id y contenido distinto.
        await store.docs.delete('*', parts[1]);
        await store.docs.put(doc.kind ?? 'doc', parts[1], doc);
        return doc;
      }, 'Guardado.');
    }

    return send(res, 404, 'no existe');
  } catch (err) {
    console.error(err);
    send(res, 500, `<pre>${err.message}</pre>`);
  }
});

// Solo la consola siembra: es la superficie de escritura. El publisher sirve lo
// que haya, y si no hay nada, no hay nada — no es su papel crear estado.
const seed = await seedIfEmpty(store, ROOT);
if (seed.seeded.length) {
  console.log(`siembra inicial: ${seed.seeded.length} documento(s) — ${seed.seeded.join(', ')}`);
}

server.listen(PORT, () => {
  console.log(`consola escuchando en :${PORT} · almacen ${store.kind} · escritura autenticada`);
});
