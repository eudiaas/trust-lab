// Las operaciones. Ni imprimen ni renderizan: reciben el almacen y devuelven
// un resultado.
//
// Existe porque hay dos frontales —el CLI y la consola— y las operaciones no
// pueden vivir dos veces. Es el mismo problema que este proyecto lleva
// documentando toda la sesion en otros sitios (la logica del fallback AV
// duplicada en espuni, el vocabulario de la norma copiado a mano): dos copias
// de una regla acaban divergiendo, y la que diverge en una fabrica de
// certificados no se nota hasta que una wallet dice que no.
import { mintCa, mintLeaf, mintTlSigner, assertTlsoProfile, mintRoleSigner, SIGNER_ROLES } from '../../ca/src/index.mjs';
import { mintWrpac, assertWrpacProfile } from '../../ca/src/wrpac.mjs';
import { inMemorySigner } from '../../signer/src/index.mjs';
import { buildTrustedListXml, signTrustedListXml, assertAnnexB } from '../../tl-xml/src/index.mjs';
import { AV_TL_PROFILE, assertAvProfile } from '../../tl-xml/src/av-profile.mjs';
import { buildLote, signLoteCompact, verifyLoteCompact, assertLote, LIST_PROFILES } from '../../lote/src/index.mjs';
import { buildWrprc, signWrprcCompact, assertWrprc, decodeWRPRC, detectEdition, droppedByEdition } from '../../wrprc/src/index.mjs';
import { assertRegistry, toWrpacSpec, toWrprcInput, newRegistry } from '../../registry/src/index.mjs';
import { signStatusListCompact, readStatus, STATUS_BY_NAME } from '../../status/src/index.mjs';
import { TrustedListProfiles, loadTrustedList, getTrustAnchors } from '@owf/eudi-tl';

export class OpError extends Error {
  constructor(message, details = []) {
    super(message);
    this.name = 'OpError';
    this.details = details;
  }
}

const P256 = { name: 'ECDSA', namedCurve: 'P-256' };

async function loadDoc(store, id) {
  const doc = await store.docs.get('*', id);
  if (!doc) throw new OpError(`no existe el documento "${id}" en el almacen`);
  return doc;
}

async function loadKey(store, name) {
  const doc = await store.keys.get(name);
  if (!doc) throw new OpError(`no existe la clave "${name}" en el almacen`);
  return doc;
}

async function importSigner(store, crypto, name) {
  const stored = await loadKey(store, name);
  const key = await crypto.subtle.importKey('jwk', stored.key, P256, true, ['sign']);
  return { stored, signer: inMemorySigner(key, stored.crt, crypto) };
}

async function saveKeyChain(store, crypto, name, material) {
  const jwk = await crypto.subtle.exportKey('jwk', material.keys.privateKey);
  await store.keys.put(name, {
    name,
    subject: material.cert.subject,
    key: jwk,
    crt: material.chainPem ?? [material.pem],
  });
  return { name, subject: material.cert.subject };
}

/** CA raiz autofirmada, o hoja firmada por otra clave del almacen. */
export async function mintKey(store, crypto, { name, subject, issuer }) {
  if (!issuer) return saveKeyChain(store, crypto, name, await mintCa(crypto, { subject }));
  const stored = await loadKey(store, issuer);
  const caKey = await crypto.subtle.importKey('jwk', stored.key, P256, true, ['sign']);
  const { X509Certificate } = await import('@peculiar/x509');
  const ca = { keys: { privateKey: caKey }, cert: new X509Certificate(stored.crt[0]), pem: stored.crt[0] };
  return saveKeyChain(store, crypto, name, await mintLeaf(crypto, ca, { subject }));
}

/**
 * Firmante de credenciales o atestaciones: DS del PID, firmante de WRPRC,
 * de Wallet Instance Attestation o de Key Attestation.
 *
 * Siempre cuelga de una CA del almacen. Es el punto: lo que hace util a este
 * certificado no es su perfil, es que su ancla sea la que publica la lista
 * correspondiente. Emitirlo sin CA no tendria sentido y por eso no se permite.
 */
export async function mintSigner(store, crypto, { name, issuer, role, subject, validityDays }) {
  const spec = SIGNER_ROLES[role];
  if (!spec) {
    throw new OpError(`rol desconocido: ${role}`, [`usa uno de: ${Object.keys(SIGNER_ROLES).join(', ')}`]);
  }
  if (!issuer) throw new OpError('un firmante siempre cuelga de una CA: falta el emisor');
  const stored = await loadKey(store, issuer);
  const { X509Certificate } = await import('@peculiar/x509');
  const issuerCert = new X509Certificate(stored.crt[0]);
  if (!issuerCert.getExtension('2.5.29.19')?.ca) {
    throw new OpError(`"${issuer}" no es una CA: no puede emitir un firmante`);
  }
  const caKey = await crypto.subtle.importKey('jwk', stored.key, P256, true, ['sign']);
  const ca = { keys: { privateKey: caKey }, cert: issuerCert, pem: stored.crt[0] };

  const material = await mintRoleSigner(crypto, ca, { role, subject, validityDays });
  await saveKeyChain(store, crypto, name, material);
  return { name, subject: material.cert.subject, role, issuer, spec };
}

/** Firmante de listas con el perfil de la clausula 5.7.1, derivado del esquema. */
export async function mintTlso(store, crypto, { name, schemeId }) {
  const state = await loadDoc(store, schemeId);
  const tlso = await mintTlSigner(crypto, {
    schemeOperatorName: state.schemeOperatorName,
    territory: state.territory,
    signerCountry: state.signerCountry,
    commonName: `${state.schemeOperatorName} TL Signer`,
  });
  const { errors, warnings } = assertTlsoProfile(tlso.pem, state);
  if (errors.length) throw new OpError('el certificado no cumple la clausula 5.7.1', errors);
  return { ...(await saveKeyChain(store, crypto, name, tlso)), warnings };
}

/** AV Trusted List: XML de TS 119 612 + XAdES, verificada antes de guardarse. */
export async function buildAvList(store, crypto, { id, signerName }) {
  const state = await loadDoc(store, id);
  const { stored, signer } = await importSigner(store, crypto, signerName);

  const tlso = assertTlsoProfile(stored.crt[0], state);
  if (tlso.errors.length) throw new OpError('el firmante no cumple el perfil TLSO (clausula 5.7.1)', tlso.errors);

  state.pointerToSelf = { signerCertPem: stored.crt[0], mimeType: AV_TL_PROFILE.mimeType };
  const avProblems = assertAvProfile(state);
  if (avProblems.length && !state.allowDivergence) {
    throw new OpError('el estado no cumple el perfil de la AV Trusted List', avProblems);
  }

  state.sequenceNumber += 1;
  const profile = TrustedListProfiles[state.profile];
  const signed = await signTrustedListXml(buildTrustedListXml(state, profile), signer, crypto);

  const annexB = assertAnnexB(signed);
  if (annexB.length) throw new OpError('la firma no cumple el Annex B de TS 119 612', annexB);

  // Verificacion con la MISMA libreria que usan EUDIPLO y el camino ZK, y
  // ANTES de guardar: nunca se publica un artefacto que no valida.
  const anchorDer = new Uint8Array(Buffer.from(stored.crt[0].replace(/-----[^-]+-----|\s/g, ''), 'base64'));
  const tl = await loadTrustedList(signed, { trustAnchors: [anchorDer] });
  const anchors = getTrustAnchors(tl, { serviceTypes: profile.serviceTypes });

  const artifact = await store.artifacts.put({
    kind: 'lists', id, sequence: state.sequenceNumber, signer: signerName,
    contentType: 'application/vnd.etsi.tsl+xml', body: signed, nextUpdate: tl.nextUpdate,
  });
  await store.docs.put(state.kind, id, state);

  return { id, sequence: state.sequenceNumber, artifact, nextUpdate: tl.nextUpdate,
    anchors: anchors.length, warnings: tlso.warnings, url: state.url };
}

/** Lista LoTE (TS 119 602), verificada antes de guardarse. */
export async function buildLoteList(store, crypto, { id, signerName }) {
  const state = await loadDoc(store, id);
  const { stored, signer } = await importSigner(store, crypto, signerName);

  state.sequenceNumber += 1;
  const lote = buildLote(state);
  const problems = assertLote(lote, state);
  if (problems.length) throw new OpError(`la lista no cumple el perfil ${state.loteType}`, problems);

  const jws = await signLoteCompact(lote, signer, `${signerName}-${state.sequenceNumber}`);
  const check = await verifyLoteCompact(jws, stored.crt[0]);

  const artifact = await store.artifacts.put({
    kind: 'lote', id, sequence: state.sequenceNumber, signer: signerName,
    contentType: 'application/jwt', body: jws, nextUpdate: check.nextUpdate,
  });
  await store.docs.put(state.kind, id, state);

  const profile = LIST_PROFILES[state.loteType];
  return { id, sequence: state.sequenceNumber, artifact, nextUpdate: check.nextUpdate,
    entities: check.entities, url: state.url, nonNormative: profile?.nonNormative };
}

/** Cambia una posicion de la status list. NO publica: hay que reemitir. */
export async function setStatus(store, { id, idx, status, note }) {
  if (!(status in STATUS_BY_NAME)) throw new OpError(`estado desconocido: ${status}`);
  const state = await loadDoc(store, id);
  state.entries[idx] = { status, ...(note ? { note } : {}), changedAt: new Date().toISOString() };
  await store.docs.put(state.kind, id, state);
  return { id, idx, status, pendingPublish: true };
}

export async function buildStatusList(store, crypto, { id, signerName }) {
  const state = await loadDoc(store, id);
  const { signer } = await importSigner(store, crypto, signerName);
  state.sequenceNumber += 1;
  const jwt = await signStatusListCompact(state, signer);
  const artifact = await store.artifacts.put({
    kind: 'status', id, sequence: state.sequenceNumber, signer: signerName,
    contentType: 'application/statuslist+jwt', body: jwt,
    nextUpdate: new Date(Date.now() + (state.expiresInDays ?? 30) * 86400000).toISOString(),
  });
  await store.docs.put(state.kind, id, state);
  const revoked = Object.values(state.entries).filter((e) => e.status !== 'valid').length;
  return { id, sequence: state.sequenceNumber, artifact, size: state.size, revoked, url: state.url };
}

export async function checkStatus(store, { id, idx, signerName }) {
  const stored = await loadKey(store, signerName);
  const artifact = await store.artifacts.latest('status', id);
  if (!artifact) throw new OpError(`no hay ninguna status list emitida para "${id}"`);
  return readStatus(artifact.body, stored.crt[0], Number(idx));
}

/**
 * Quita una entrada de una lista. NO publica: hay que reemitir.
 *
 * Hace falta porque `state/` viene sembrado con un proveedor de ejemplo por
 * lista, y sus claves privadas no existen en ningun sitio: son anclas que
 * nadie puede usar. Un despliegue nuevo tiene que sustituirlas por las suyas,
 * y hasta ahora la unica via era editar el JSON a mano.
 */
export async function removeProvider(store, { id, ref }) {
  const state = await loadDoc(store, id);
  const list = state.providers ?? [];
  const idx = /^\d+$/.test(String(ref)) ? Number(ref) : list.findIndex((p) => p.name === ref);
  if (idx < 0 || idx >= list.length) {
    throw new OpError(`no hay ninguna entrada "${ref}" en ${id}`, list.map((p, i) => `${i}: ${p.name}`));
  }
  const [gone] = list.splice(idx, 1);
  await store.docs.put(state.kind, id, state);
  return { id, removed: gone.name, remaining: list.length, pendingPublish: true };
}

/** Access certificate del RP, derivado del registro (GEN-6.6.1-10). */
export async function issueWrpac(store, crypto, { registryId, serviceId, caName, keyName }) {
  const registry = await loadDoc(store, registryId);
  const problems = assertRegistry(registry);
  if (problems.length) throw new OpError('el registro no cumple el modelo de TS5/TS6', problems);

  const stored = await loadKey(store, caName);
  const caKey = await crypto.subtle.importKey('jwk', stored.key, P256, true, ['sign']);
  const { X509Certificate } = await import('@peculiar/x509');
  const ca = { keys: { privateKey: caKey }, cert: new X509Certificate(stored.crt[0]), pem: stored.crt[0] };

  const wrpac = await mintWrpac(crypto, ca, toWrpacSpec(registry, serviceId));
  const bad = assertWrpacProfile(wrpac.pem);
  if (bad.length) throw new OpError('el certificado no cumple el perfil de TS 119 411-8', bad);

  const name = keyName ?? `${registryId}-${serviceId}-access`;
  await saveKeyChain(store, crypto, name, wrpac);
  return { name, subject: wrpac.cert.subject, policy: wrpac.policy, policyOid: wrpac.policyOid };
}

/** Un WRPRC se identifica por registro + servicio + finalidad, en ese orden. */
export const wrprcArtifactId = (registryId, serviceId, useId) => `${registryId}-${serviceId}-${useId}`;

/** Registration certificate: uno por finalidad (TS5 §2.4.4). */
export async function issueWrprc(store, crypto, { registryId, serviceId, useId, signerName }) {
  const registry = await loadDoc(store, registryId);
  const problems = assertRegistry(registry);
  if (problems.length) throw new OpError('el registro no cumple el modelo de TS5/TS6', problems);

  const { signer } = await importSigner(store, crypto, signerName);
  const sl = registry.statusList;
  const idx = sl?.indexByIntendedUse?.[useId];

  const payload = buildWrprc(toWrprcInput(registry, serviceId, useId), {
    statusListUri: sl?.uri,
    statusListIdx: idx,
  });
  const bad = assertWrprc(payload);
  if (bad.length) throw new OpError('el payload no valida contra TS 119 475', bad);

  const jwt = await signWrprcCompact(payload, signer, signerName);
  // El id lleva el registro delante: TS5 no exige que `serviceIdentifier` sea
  // unico entre relying parties, asi que dos RP con el mismo par
  // servicio/finalidad —el caso normal cuando las dos salen del mismo
  // esqueleto— se pisarian el certificado la una a la otra sin decir nada.
  const artifactId = wrprcArtifactId(registryId, serviceId, useId);
  const artifact = await store.artifacts.put({
    kind: 'wrprc', id: artifactId, sequence: Math.floor(Date.now() / 1000), signer: signerName,
    contentType: 'application/jwt', body: jwt,
  });

  const back = decodeWRPRC(jwt);
  return {
    id: artifactId, artifact,
    subject: payload.sub_ln ?? payload.name,
    entitlements: payload.entitlements.length,
    edition: detectEdition(back.header ?? {}, back.payload ?? back),
    statusUri: sl?.uri, statusIndex: idx,
    dropped: droppedByEdition(registry),
  };
}

// ---------------------------------------------------------------------------
// Exportacion
//
// Emitir un certificado y no poder sacarlo lo deja donde no sirve: el access
// certificate lo usa el RP en su propio despliegue y el registration
// certificate viaja dentro de la peticion OID4VP. Asi que la fabrica tiene que
// tener puerta de salida, y tiene que ser ESTA superficie —la autenticada— y
// no el publisher, que a proposito no puede descifrar ninguna clave.
// ---------------------------------------------------------------------------

const wrapPem = (label, b64) =>
  [`-----BEGIN ${label}-----`, ...(b64.match(/.{1,64}/g) ?? []), `-----END ${label}-----`].join('\n');

export const KEY_FORMS = {
  chain: { ext: 'crt.pem', contentType: 'application/x-pem-file', secret: false },
  key: { ext: 'key.pem', contentType: 'application/x-pem-file', secret: true },
  bundle: { ext: 'pem', contentType: 'application/x-pem-file', secret: true },
  jwk: { ext: 'jwk.json', contentType: 'application/json', secret: true },
};

/**
 * Material de una clave del almacen, en la forma que pida quien la consume.
 *
 * `chain` es lo unico que no es secreto: es el certificado y su cadena, que es
 * justo lo que se pinea en el otro extremo (el `AV_TRUST_LIST_SIGNER_CERT_*`
 * de espuni, por ejemplo). Las otras tres llevan la privada dentro.
 */
export async function exportKey(store, crypto, { name, form = 'chain' }) {
  const spec = KEY_FORMS[form];
  if (!spec) throw new OpError(`formato desconocido: ${form}`, [`usa uno de: ${Object.keys(KEY_FORMS).join(', ')}`]);
  const stored = await loadKey(store, name);
  const chain = (stored.crt ?? []).join('\n');
  if (!chain) throw new OpError(`la clave "${name}" no tiene certificado`);

  if (form === 'chain') {
    return { filename: `${name}.${spec.ext}`, contentType: spec.contentType, body: `${chain}\n`, secret: false };
  }
  if (form === 'jwk') {
    const { pemToBase64Der } = await import('../../signer/src/index.mjs');
    const body = JSON.stringify({ ...stored.key, x5c: (stored.crt ?? []).map(pemToBase64Der) }, null, 2);
    return { filename: `${name}.${spec.ext}`, contentType: spec.contentType, body, secret: true };
  }

  const key = await crypto.subtle.importKey('jwk', stored.key, P256, true, ['sign']);
  const pkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', key)).toString('base64');
  const keyPem = wrapPem('PRIVATE KEY', pkcs8);
  const body = form === 'key' ? `${keyPem}\n` : `${keyPem}\n${chain}\n`;
  return { filename: `${name}.${spec.ext}`, contentType: spec.contentType, body, secret: true };
}

/** Un artefacto emitido, byte a byte como se publicaria. */
export async function exportArtifact(store, { kind, id, sequence }) {
  const a = sequence
    ? await store.artifacts.get(kind, id, Number(sequence))
    : await store.artifacts.latest(kind, id);
  if (!a) throw new OpError(`no hay ningun artefacto "${kind}/${id}"${sequence ? ` con secuencia ${sequence}` : ''}`);
  const ext = { wrprc: 'jwt', lote: 'jws', status: 'jws', lists: 'xml' }[kind] ?? 'txt';
  return {
    filename: `${id}-${a.sequence}.${ext}`,
    contentType: a.contentType ?? 'application/octet-stream',
    body: a.body,
    sequence: a.sequence,
    secret: false,
  };
}

// ---------------------------------------------------------------------------
// Alta de relying party
// ---------------------------------------------------------------------------

/** Posiciones de la lista de revocacion que ya tiene reservadas algun registro. */
async function takenIndexes(store, listId) {
  const taken = new Set();
  for (const doc of await store.docs.list('*')) {
    if (!doc.walletRelyingParty || doc.statusList?.listId !== listId) continue;
    for (const idx of Object.values(doc.statusList.indexByIntendedUse ?? {})) taken.add(Number(idx));
  }
  return taken;
}

/**
 * Da de alta una relying party con un esqueleto valido y, si se le indica una
 * lista de revocacion, le reserva una posicion libre.
 *
 * Reservarla aqui y no al emitir el WRPRC es deliberado: dos altas que eligen
 * la misma posicion se detectan al crear la entidad, cuando no cuesta nada,
 * y no al emitir el certificado, cuando ya hay material firmado apuntando a
 * una posicion compartida — que es como se revocan dos RP de golpe.
 */
export async function createRp(store, { id, statusListId, ...rest }) {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(id ?? '')) {
    throw new OpError('el identificador solo admite minusculas, digitos y guiones', [`recibido: "${id ?? ''}"`]);
  }
  if (await store.docs.get('*', id)) throw new OpError(`ya existe un documento con el id "${id}"`);

  let statusList;
  let baseUrl = rest.baseUrl;
  if (statusListId) {
    const list = await store.docs.get('*', statusListId);
    if (!list) throw new OpError(`no existe la lista de revocacion "${statusListId}"`);
    const taken = await takenIndexes(store, statusListId);
    let idx = 0;
    while (taken.has(idx)) idx += 1;
    if (idx >= (list.size ?? 0)) {
      throw new OpError(`la lista "${statusListId}" no tiene posiciones libres`, [`tamano ${list.size}`]);
    }
    statusList = {
      listId: statusListId,
      uri: list.url,
      indexByIntendedUse: { [rest.intendedUseId ?? 'use-1']: idx },
    };
    // La URL de la lista es la unica pista fiable del dominio con el que se
    // esta operando: el resto de URLs del esqueleto salen de ahi.
    if (!baseUrl && list.url) {
      try { baseUrl = new URL(list.url).origin; } catch { /* se queda el default */ }
    }
  }

  const doc = newRegistry({ ...rest, baseUrl: baseUrl ?? rest.baseUrl, statusList });
  const problems = assertRegistry(doc);
  if (problems.length) throw new OpError('el esqueleto no valida', problems);
  // El mismo `kind` que usa el editor: en SQL la clave primaria es (kind, id),
  // asi que crear con uno y guardar con otro dejaria DOS filas con el mismo id
  // y `get('*', id)` devolveria la que saliera primero.
  await store.docs.put('doc', id, doc);
  return { id, legalName: doc.walletRelyingParty.legalName, statusList, doc };
}

// ---------------------------------------------------------------------------
// Borrado
//
// Toda operacion de borrado consulta el MISMO grafo que dibuja la pagina de
// dependencias. No hay dos ideas de "que depende de que": la que avisa y la
// que se pinta son la misma, porque una discrepancia ahi solo se nota
// borrando algo que hacia falta.
//
// El aviso no es un obstaculo que apartar: un `force` que se usa por costumbre
// no protege de nada. Por eso el mensaje dice QUE se rompe, con nombres, en
// vez de un "hay dependencias" que no ayuda a decidir.
// ---------------------------------------------------------------------------

const DEP_LABEL = {
  'emitido-por': 'cuelga de esta clave',
  'contenido-en': 'esta publicado en',
  'firmada-por': 'esta firmada por esta clave',
  'firmado-por': 'esta firmado por esta clave',
  'revocable-en': 'se revoca en',
  'access-cert': 'usa esta clave como access certificate',
  de: 'pertenece a',
};

async function checkDependents(store, id, { force }) {
  const { buildGraph, dependents } = await import('../../graph/src/index.mjs');
  const graph = await buildGraph(store);
  const node = graph.nodes.find((n) => n.id === id);
  if (!node) throw new OpError(`no existe "${id}"`);
  const deps = dependents(graph, id).map((e) => {
    const from = graph.nodes.find((n) => n.id === e.from);
    return `${from?.label ?? e.from} ${DEP_LABEL[e.type] ?? e.type}`;
  });
  if (deps.length && !force) {
    throw new OpError(`no se borra "${node.label}": ${deps.length} cosa(s) dependen de el`, [
      ...deps,
      'repite con force para borrarlo igualmente y dejar esas cadenas rotas',
    ]);
  }
  return { node, broke: deps };
}

/** Borra una clave con su certificado. */
export async function deleteKey(store, { name, force = false }) {
  const { node, broke } = await checkDependents(store, `key:${name}`, { force });
  await store.keys.delete(name);
  return { deleted: node.label, broke };
}

/** Borra un registro de relying party, y con el sus certificados de servicio. */
export async function deleteRp(store, { id, force = false }) {
  const doc = await loadDoc(store, id);
  if (!doc.walletRelyingParty) throw new OpError(`"${id}" no es un registro de relying party`);
  const { node, broke } = await checkDependents(store, `rp:${id}`, { force: true });

  // Sus propios certificados no cuentan como dependencia externa: son suyos y
  // se van con el. Lo que si cuenta es cualquier otra cosa.
  const propios = new Set();
  for (const svc of doc.walletRelyingParty.services ?? []) {
    propios.add(`${id}-${svc.serviceIdentifier}-access`);
    for (const u of svc.intendedUses ?? []) {
      propios.add(`${id}-${svc.serviceIdentifier}-${u.intendedUseIdentifier}`);
    }
  }
  const ajenas = broke.filter((b) => ![...propios].some((p) => b.includes(p)));
  if (ajenas.length && !force) {
    throw new OpError(`no se borra "${node.label}": hay dependencias externas`, [
      ...ajenas,
      'repite con force para borrarlo igualmente',
    ]);
  }

  const retirados = [];
  for (const svc of doc.walletRelyingParty.services ?? []) {
    const key = `${id}-${svc.serviceIdentifier}-access`;
    if (await store.keys.get(key).catch(() => null)) {
      await store.keys.delete(key);
      retirados.push(`clave ${key}`);
    }
    for (const u of svc.intendedUses ?? []) {
      const aid = wrprcArtifactId(id, svc.serviceIdentifier, u.intendedUseIdentifier);
      if (await store.artifacts.latest('wrprc', aid)) {
        await store.artifacts.delete('wrprc', aid);
        retirados.push(`WRPRC ${aid}`);
      }
    }
  }
  await store.docs.delete('*', id);
  return { deleted: doc.walletRelyingParty.legalName ?? id, retirados };
}

/**
 * Retira lo publicado de un documento sin tocar el documento.
 *
 * Es el borrado que hace falta cuando una lista salio con un ancla que no
 * encadena: se retira, se corrige el estado y se reemite. Deja el documento
 * intacto a proposito — perderlo obligaria a reconstruirlo entero.
 */
export async function unpublish(store, { id }) {
  const doc = await loadDoc(store, id);
  const kind = { 'etsi-tl-xml': 'lists', 'lote-json': 'lote', 'token-status-list': 'status' }[doc.kind];
  if (!kind) throw new OpError(`"${id}" no es un documento publicable`);
  const a = await store.artifacts.latest(kind, id);
  if (!a) throw new OpError(`"${id}" no tiene nada publicado`);
  await store.artifacts.delete(kind, id);
  return { id, kind, retirada: a.sequence, url: doc.url };
}

/** Borra un WRPRC emitido. El registro y su posicion de revocacion se quedan. */
export async function deleteWrprc(store, { id }) {
  const a = await store.artifacts.latest('wrprc', id);
  if (!a) throw new OpError(`no hay ningun WRPRC "${id}"`);
  await store.artifacts.delete('wrprc', id);
  return { deleted: id, sequence: a.sequence };
}

// ---------------------------------------------------------------------------
// Reinicio
//
// Existe porque la alternativa era pedirle al operador que abriera la pestana
// de datos de Railway y escribiera un DROP TABLE. Eso no es mas seguro por ser
// mas incomodo: es igual de destructivo, sin inventario previo, sin frase de
// confirmacion y sin resembrado.
//
// El inventario ANTES de borrar es la pieza que importa. «Vas a perder 7
// claves» no dice nada; «vas a perder tl-signer, que firma las cinco listas»
// si.
// ---------------------------------------------------------------------------

const PUBLICABLE = { 'etsi-tl-xml': 'lists', 'lote-json': 'lote', 'token-status-list': 'status' };

/** Que se llevaria por delante un reinicio, con nombres. */
export async function resetPreview(store) {
  const docs = await store.docs.list('*');
  const publicado = [];
  const wrprc = [];
  for (const doc of docs) {
    const kind = PUBLICABLE[doc.kind];
    if (kind) {
      const a = await store.artifacts.latest(kind, doc.id);
      if (a) publicado.push({ kind, id: doc.id, sequence: a.sequence, url: doc.url ?? null });
      continue;
    }
    for (const svc of doc.walletRelyingParty?.services ?? []) {
      for (const u of svc.intendedUses ?? []) {
        const id = wrprcArtifactId(doc.id, svc.serviceIdentifier, u.intendedUseIdentifier);
        if (await store.artifacts.latest('wrprc', id)) wrprc.push(id);
      }
    }
  }
  const keys = [];
  const raw = store.rawKeys ?? store.keys;
  for (const name of await store.keys.list()) {
    const doc = await raw.get(name).catch(() => null);
    keys.push({ name, subject: doc?.subject ?? null });
  }
  return {
    publicado, wrprc, keys,
    docs: docs.map((d) => ({ id: d.id, kind: d.kind, esRp: !!d.walletRelyingParty })),
  };
}

/**
 * Reinicia el almacen.
 *
 * `scope: 'publicado'` retira todo lo emitido y deja claves y documentos: es el
 * reinicio reversible, el que sirve cuando algo salio mal encadenado y hay que
 * reemitirlo todo. `scope: 'todo'` borra ademas claves y documentos, y vuelve a
 * sembrar `state/` — eso si es irreversible: las privadas estan cifradas ahi y
 * en ningun otro sitio.
 *
 * Se enumera y se borra elemento a elemento en vez de vaciar tablas: la
 * operacion tiene que funcionar igual sobre los tres adaptadores, y solo uno
 * tiene tablas.
 */
export async function reset(store, { scope = 'publicado', confirm, root } = {}) {
  const FRASE = { publicado: 'RETIRAR', todo: 'BORRAR TODO' }[scope];
  if (!FRASE) throw new OpError(`alcance desconocido: ${scope}`, ['usa "publicado" o "todo"']);
  if (confirm !== FRASE) {
    throw new OpError('la frase de confirmacion no coincide', [`hay que escribir exactamente: ${FRASE}`]);
  }

  const previo = await resetPreview(store);
  for (const a of previo.publicado) await store.artifacts.delete(a.kind, a.id);
  for (const id of previo.wrprc) await store.artifacts.delete('wrprc', id);
  const retirados = previo.publicado.length + previo.wrprc.length;

  if (scope === 'publicado') {
    return { scope, retirados, claves: 0, documentos: 0, sembrados: [] };
  }

  for (const k of previo.keys) await store.keys.delete(k.name);
  for (const d of previo.docs) await store.docs.delete('*', d.id);

  let sembrados = [];
  if (root) {
    const { seedIfEmpty } = await import('../../store/src/index.mjs');
    sembrados = (await seedIfEmpty(store, root)).seeded;
  }
  return { scope, retirados, claves: previo.keys.length, documentos: previo.docs.length, sembrados };
}
