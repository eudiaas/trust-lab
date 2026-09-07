#!/usr/bin/env node
// El publisher: sirve lo emitido, y nada mas.
//
// Es de SOLO LECTURA por diseno, no por falta de tiempo. Una fabrica de CAs con
// endpoints de escritura expuestos es un objetivo goloso; aqui la escritura vive
// en el CLI (y manana en la UI, tras login), y este proceso solo publica lo que
// aquel firmo. No hay una sola ruta que escriba en el almacen.
//
// Sin framework, a proposito: `node:http` basta para servir bytes ya firmados y
// deja la superficie de dependencias en lo minimo.
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { openStore } from '../../packages/store/src/index.mjs';

const ROOT = join(dirname(new URL(import.meta.url).pathname), '../..');
const PORT = Number(process.env.PORT ?? 8080);

// Cuanto puede cachear un intermediario. El tope existe porque una lista se
// puede reemitir antes de su NextUpdate (una revocacion no espera), y el suelo
// porque servir sin cache una lista que cambia cada 30 dias es tirar ancho de
// banda.
const MIN_MAX_AGE = 60;
const MAX_MAX_AGE = Number(process.env.MAX_CACHE_SECONDS ?? 3600);

// Que se publica en cada ruta. El `kind` es interno del almacen; la URL es
// contrato publico y se fija aqui (contrato 4).
const ROUTES = {
  lists: { kind: 'lists', contentType: 'application/vnd.etsi.tsl+xml' },
  lote: { kind: 'lote', contentType: 'application/jwt' },
  status: { kind: 'status', contentType: 'application/statuslist+jwt' },
};

/**
 * El publisher NO abre el almacen de claves ni lo necesita: sirve artefactos ya
 * firmados. Por eso tampoco pide TRUST_LAB_KEY — desplegarlo no expone el
 * material privado ni siquiera a su propio proceso.
 */
// Un fallo de configuracion —falta la base de datos, falta la clave— es un
// mensaje que el operador tiene que poder leer en los logs de Railway, no una
// pila de llamadas.
const store = await openStore({ root: ROOT, needsKeys: false }).catch((err) => {
  console.error(`error: ${err.message}`);
  process.exit(1);
});

const stripExt = (s) => s.replace(/\.(xml|json|jwt)$/, '');

const maxAgeFor = (nextUpdate) => {
  if (!nextUpdate) return MIN_MAX_AGE;
  const secs = Math.floor((new Date(nextUpdate).getTime() - Date.now()) / 1000);
  return Math.max(MIN_MAX_AGE, Math.min(MAX_MAX_AGE, secs));
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(body);
}

async function serveArtifact(req, res, route, id, sequence) {
  const artifact = sequence
    ? await store.artifacts.get(route.kind, id, Number(sequence))
    : await store.artifacts.latest(route.kind, id);
  if (!artifact) return send(res, 404, 'not found\n', { 'Content-Type': 'text/plain' });

  const etag = `"${createHash('sha256').update(artifact.body).digest('base64url').slice(0, 27)}"`;
  if (req.headers['if-none-match'] === etag) {
    return send(res, 304, '', { ETag: etag });
  }

  send(res, 200, artifact.body, {
    'Content-Type': artifact.contentType ?? route.contentType,
    ETag: etag,
    // Una version historica es inmutable: se puede cachear para siempre. La
    // ultima, no: puede cambiar en cuanto alguien revoque algo.
    'Cache-Control': sequence
      ? 'public, max-age=31536000, immutable'
      : `public, max-age=${maxAgeFor(artifact.nextUpdate)}`,
    ...(artifact.nextUpdate ? { 'X-Next-Update': new Date(artifact.nextUpdate).toISOString() } : {}),
    'Access-Control-Allow-Origin': '*',
  });
}

const server = createServer(async (req, res) => {
  try {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      // No es un 404: decir 405 deja claro que este servicio no escribe nunca,
      // en vez de sugerir que la ruta podria existir con otro nombre.
      return send(res, 405, 'este servicio es de solo lectura\n', {
        'Content-Type': 'text/plain',
        Allow: 'GET, HEAD',
      });
    }

    const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
    const parts = url.pathname.split('/').filter(Boolean);

    if (parts.length === 0) return serveIndex(res);
    if (parts[0] === 'health') return send(res, 200, 'ok\n', { 'Content-Type': 'text/plain' });

    const route = ROUTES[parts[0]];
    if (!route) return send(res, 404, 'not found\n', { 'Content-Type': 'text/plain' });

    // /lists/av-lab.xml  ·  /lists/av-lab/8.xml (version historica)
    if (parts.length === 2) {
      return serveArtifact(req, res, route, stripExt(parts[1]));
    }
    if (parts.length === 3) {
      return serveArtifact(req, res, route, parts[1], stripExt(parts[2]));
    }
    return send(res, 404, 'not found\n', { 'Content-Type': 'text/plain' });
  } catch (err) {
    console.error(err);
    send(res, 500, 'error\n', { 'Content-Type': 'text/plain' });
  }
});

/** Indice legible por maquina de lo publicado. Util para el operador y para CI. */
async function serveIndex(res) {
  const docs = await store.docs.list('*');
  const published = [];
  for (const [prefix, route] of Object.entries(ROUTES)) {
    for (const doc of docs) {
      const artifact = await store.artifacts.latest(route.kind, doc.id);
      if (!artifact) continue;
      published.push({
        url: `/${prefix}/${doc.id}`,
        kind: route.kind,
        id: doc.id,
        sequence: artifact.sequence,
        contentType: artifact.contentType ?? route.contentType,
        nextUpdate: artifact.nextUpdate ?? null,
        declaredUrl: doc.url ?? null,
      });
    }
  }
  send(res, 200, JSON.stringify({ service: 'trust-lab publisher', readOnly: true, published }, null, 2) + '\n', {
    'Content-Type': 'application/json',
  });
}

server.listen(PORT, () => {
  console.log(`publisher escuchando en :${PORT} · almacen ${store.kind} · solo lectura`);
  // Sintoma tipico del primer despliegue: los dos servicios arrancan el
  // publisher porque al de la consola le falta TRUST_LAB_APP, y como los dos
  // responden se tarda en ver que pasa. Si este proceso tiene la contrasena de
  // la consola, casi seguro que se pretendia que FUERA la consola.
  if (process.env.CONSOLE_PASSWORD) {
    console.warn(
      'aviso: este servicio corre como PUBLISHER pero tiene CONSOLE_PASSWORD en el ' +
        'entorno. Si querias la consola, define TRUST_LAB_APP=console y redespliega.',
    );
  }
});
