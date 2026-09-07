// El grafo de dependencias criptograficas del almacen.
//
// Es el modelo del que salen las DOS cosas que hacen falta encima: la
// visualizacion y el borrado seguro. Y tiene que ser uno solo: un borrado que
// avisa segun una idea de las dependencias, y un dibujo que las pinta segun
// otra, acaban discrepando justo cuando importa.
//
// La union se hace por HUELLA del certificado, nunca por nombre. Dos
// certificados pueden compartir DN completo y ser claves distintas —pasa cada
// vez que se remonta el laboratorio— y unir por nombre daria una cadena que
// parece cerrada y no lo esta.
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { createHash } from 'node:crypto';

const KIND_OF = { 'etsi-tl-xml': 'lists', 'lote-json': 'lote', 'token-status-list': 'status' };

/** SHA-256 del DER. Es la identidad de un certificado a estos efectos. */
export function fingerprint(pem) {
  const der = Buffer.from(String(pem).replace(/-----[^-]+-----|\s/g, ''), 'base64');
  return createHash('sha256').update(der).digest('hex');
}

const short = (fp) => fp.slice(0, 12);

function parse(pem) {
  try {
    return new x509.X509Certificate(pem);
  } catch {
    return null;
  }
}

/**
 * Construye el grafo entero.
 *
 * Nodos: claves (par clave+certificado), documentos de lista, registros de
 * relying party y artefactos emitidos.
 * Aristas, todas dirigidas «de lo que depende» → «de lo que se depende»:
 *
 *   emitido-por    hoja → CA que la firmo
 *   contenido-en   clave → lista que publica su certificado como ancla
 *   firma          artefacto → clave que lo firmo
 *   revocable-en   artefacto WRPRC → status list donde tiene posicion
 *   usa            registro de RP → clave (su access certificate)
 */
export async function buildGraph(store) {
  const nodes = new Map();
  const edges = [];
  const add = (n) => (nodes.set(n.id, { ...(nodes.get(n.id) ?? {}), ...n }), n.id);
  const link = (from, to, type, label) => {
    if (from && to && nodes.has(from) && nodes.has(to)) edges.push({ from, to, type, label });
  };

  // --- claves -------------------------------------------------------------
  const byFingerprint = new Map();   // huella → id de nodo
  const bySubjectKeyId = new Map();  // SKI → id de nodo (para encadenar)
  const keyNames = await store.keys.list();
  const raw = store.rawKeys ?? store.keys;

  for (const name of keyNames) {
    const doc = await raw.get(name);
    const pem = doc?.crt?.[0];
    const cert = pem ? parse(pem) : null;
    const id = `key:${name}`;
    const bc = cert?.getExtension('2.5.29.19');
    add({
      id, type: 'key', name, label: name,
      subject: doc?.subject ?? cert?.subject ?? null,
      ca: !!bc?.ca,
      notAfter: cert?.notAfter?.toISOString().slice(0, 10) ?? null,
      expired: cert?.notAfter ? cert.notAfter < new Date() : null,
      fingerprint: pem ? fingerprint(pem) : null,
      chain: (doc?.crt ?? []).map(fingerprint),
    });
    if (pem) byFingerprint.set(fingerprint(pem), id);
    const ski = cert?.getExtension('2.5.29.14');
    if (ski?.keyId) bySubjectKeyId.set(String(ski.keyId), id);
  }

  // emitido-por: por AuthorityKeyIdentifier, con el subject como respaldo
  for (const name of keyNames) {
    const doc = await raw.get(name);
    const cert = doc?.crt?.[0] ? parse(doc.crt[0]) : null;
    if (!cert || cert.subject === cert.issuer) continue;
    const aki = cert.getExtension('2.5.29.35');
    let issuerId = aki?.keyId ? bySubjectKeyId.get(String(aki.keyId)) : null;
    if (!issuerId && doc.crt?.[1]) issuerId = byFingerprint.get(fingerprint(doc.crt[1]));
    link(`key:${name}`, issuerId, 'emitido-por');
  }

  // --- listas y registros -------------------------------------------------
  const docs = await store.docs.list('*');
  for (const doc of docs) {
    if (doc.walletRelyingParty) {
      add({
        id: `rp:${doc.id}`, type: 'rp', name: doc.id,
        label: doc.walletRelyingParty.legalName ?? doc.id,
        services: (doc.walletRelyingParty.services ?? []).map((s) => s.serviceIdentifier),
      });
      continue;
    }
    const kind = KIND_OF[doc.kind];
    if (!kind) continue;

    // Una status list no es una lista de confianza y no va en su carril: no
    // dice en quien se confia, dice de que dejo de confiar QUIEN LA FIRMA. Su
    // dependencia es su emisor, no el operador de ningun esquema.
    if (doc.kind === 'token-status-list') {
      add({
        id: `status:${doc.id}`, type: 'status', name: doc.id, kind, label: doc.id,
        url: doc.url ?? null, issuerKey: doc.issuerKey ?? null, issuer: doc.issuer ?? null,
        size: doc.size ?? 0,
        gastadas: Object.keys(doc.assigned ?? {}).length,
        revocadas: Object.values(doc.entries ?? {}).filter((e) => e.status !== 'valid').length,
      });
      continue;
    }

    add({
      id: `list:${doc.id}`, type: 'list', name: doc.id, kind, docKind: doc.kind,
      label: doc.id, url: doc.url ?? null,
      loteType: doc.loteType ?? null,
      entries: (doc.providers ?? []).length,
    });
  }

  // contenido-en: la huella del ancla publicada contra la de cada clave
  for (const doc of docs) {
    if (!KIND_OF[doc.kind]) continue;
    for (const p of doc.providers ?? []) {
      for (const [field, rol] of [
        ['certPem', 'ancla'], ['issuanceCertPem', 'emision'], ['revocationCertPem', 'revocacion'],
      ]) {
        if (!p[field]) continue;
        const fp = fingerprint(p[field]);
        const keyId = byFingerprint.get(fp);
        if (keyId) link(keyId, `list:${doc.id}`, 'contenido-en', p.name);
        else {
          // Un ancla publicada cuya clave privada no esta en el almacen. Es
          // exactamente el caso de las listas sembradas, y es una fuga de
          // confianza: la lista dice "confia en esto" y nadie puede emitir con
          // ello. Se pinta como nodo huerfano para que se vea.
          const id = `orphan:${short(fp)}`;
          add({ id, type: 'orphan', label: p.name ?? short(fp), fingerprint: fp, rol });
          link(id, `list:${doc.id}`, 'contenido-en', p.name);
        }
      }
    }
  }

  // --- artefactos ---------------------------------------------------------
  for (const doc of docs) {
    const kind = KIND_OF[doc.kind];
    if (!kind) continue;
    const a = await store.artifacts.latest(kind, doc.id);
    const nodeId = doc.kind === 'token-status-list' ? `status:${doc.id}` : `list:${doc.id}`;
    // La arista sale del emisor declarado aunque no se haya emitido nada aun:
    // en una status list eso es lo que hay que poder ver — quien podra
    // revocar — y no solo quien firmo la ultima version.
    if (doc.kind === 'token-status-list' && doc.issuerKey) {
      link(nodeId, `key:${doc.issuerKey}`, 'la-revoca');
    }
    if (!a) continue;
    nodes.get(nodeId).published = { sequence: a.sequence, nextUpdate: a.nextUpdate ?? null, signer: a.signer ?? null };
    if (a.signer && nodes.has(`key:${a.signer}`) && doc.kind !== 'token-status-list') {
      link(nodeId, `key:${a.signer}`, 'firmada-por');
    }
  }

  for (const doc of docs) {
    if (!doc.walletRelyingParty) continue;
    for (const svc of doc.walletRelyingParty.services ?? []) {
      const accessKey = `key:${doc.id}-${svc.serviceIdentifier}-access`;
      link(`rp:${doc.id}`, accessKey, 'access-cert', svc.serviceIdentifier);
      for (const u of svc.intendedUses ?? []) {
        const aid = `${doc.id}-${svc.serviceIdentifier}-${u.intendedUseIdentifier}`;
        const a = await store.artifacts.latest('wrprc', aid);
        if (!a) continue;
        add({ id: `wrprc:${aid}`, type: 'wrprc', name: aid, label: aid, sequence: a.sequence, signer: a.signer ?? null });
        link(`wrprc:${aid}`, `rp:${doc.id}`, 'de');
        if (a.signer) link(`wrprc:${aid}`, `key:${a.signer}`, 'firmado-por');
        const listId = doc.statusList?.listId;
        const idx = doc.statusList?.indexByIntendedUse?.[u.intendedUseIdentifier];
        if (listId && idx !== undefined) link(`wrprc:${aid}`, `status:${listId}`, 'revocable-en', `#${idx}`);
      }
    }
  }

  return { nodes: [...nodes.values()], edges };
}

/** Lo que depende de un nodo — es decir, lo que se rompe si desaparece. */
export function dependents(graph, id) {
  return graph.edges.filter((e) => e.to === id);
}

/**
 * Certificados cuya cadena no termina en ningun ancla publicada.
 *
 * Un certificado esta anclado si el propio certificado esta en una lista —es
 * el caso del Document Signer en la AV Trusted List— o si lo esta alguna CA
 * por encima. Comprobar solo lo segundo daria un falso positivo justo en el
 * caso mas comun del perfil AV.
 */
export function danglingChains(graph) {
  const listed = new Set(
    graph.edges.filter((e) => e.type === 'contenido-en').map((e) => e.from),
  );
  const issuerOf = new Map(
    graph.edges.filter((e) => e.type === 'emitido-por').map((e) => [e.from, e.to]),
  );

  const issuedBy = new Map();
  for (const [leaf, ca] of issuerOf) {
    if (!issuedBy.has(ca)) issuedBy.set(ca, []);
    issuedBy.get(ca).push(leaf);
  }

  // Hacia arriba: alguna CA por encima esta publicada.
  const anchoredUp = (id, seen = new Set()) => {
    if (listed.has(id)) return true;
    if (seen.has(id)) return false;
    seen.add(id);
    const up = issuerOf.get(id);
    return up ? anchoredUp(up, seen) : false;
  };

  // Y hacia abajo: en el perfil AV la lista publica el Document Signer, no la
  // IACA. Mirar solo hacia arriba marcaria como rota justo la jerarquia que el
  // perfil manda montar asi.
  const anchoredDown = (id, seen = new Set()) => {
    if (listed.has(id)) return true;
    if (seen.has(id)) return false;
    seen.add(id);
    return (issuedBy.get(id) ?? []).some((child) => anchoredDown(child, seen));
  };

  const anchored = (id) => anchoredUp(id) || anchoredDown(id);

  const out = [];
  for (const n of graph.nodes) {
    if (n.type !== 'key' || anchored(n.id)) continue;
    // El firmante de listas es la excepcion legitima: no esta en ninguna lista
    // porque es quien las firma, y su confianza se establece pineandolo.
    const firma = graph.edges.some((e) => e.to === n.id && e.type === 'firmada-por');
    if (firma) continue;
    const up = issuerOf.get(n.id);
    out.push({
      id: n.id, label: n.label,
      why: up
        ? `ni el ni su CA (${graph.nodes.find((x) => x.id === up)?.label ?? up}) estan en ninguna lista`
        : 'no esta en ninguna lista y no cuelga de nada que lo este',
    });
  }
  return out;
}
