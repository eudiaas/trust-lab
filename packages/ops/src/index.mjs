// Las operaciones. Ni imprimen ni renderizan: reciben el almacen y devuelven
// un resultado.
//
// Existe porque hay dos frontales —el CLI y la consola— y las operaciones no
// pueden vivir dos veces. Es el mismo problema que este proyecto lleva
// documentando toda la sesion en otros sitios (la logica del fallback AV
// duplicada en espuni, el vocabulario de la norma copiado a mano): dos copias
// de una regla acaban divergiendo, y la que diverge en una fabrica de
// certificados no se nota hasta que una wallet dice que no.
import { mintCa, mintLeaf, mintTlSigner, assertTlsoProfile, mintRoleSigner, signerRole, SIGNER_ROLES } from '../../ca/src/index.mjs';
import { mintWrpac, assertWrpacProfile } from '../../ca/src/wrpac.mjs';
import { inMemorySigner } from '../../signer/src/index.mjs';
import { buildTrustedListXml, signTrustedListXml, assertAnnexB } from '../../tl-xml/src/index.mjs';
import { AV_TL_PROFILE, assertAvProfile } from '../../tl-xml/src/av-profile.mjs';
import { buildLote, signLoteCompact, verifyLoteCompact, assertLote, assertIdentityNaming, staleRevocationFields, LIST_PROFILES } from '../../lote/src/index.mjs';
import { buildWrprc, signWrprcCompact, verifyWrprcCompact, assertWrprc, decodeWRPRC, detectEdition, droppedByEdition } from '../../wrprc/src/index.mjs';
import { assertRegistry, toWrpacSpec, toWrprcInput, newRegistry } from '../../registry/src/index.mjs';
import * as x509 from '@peculiar/x509';
import { randomInt } from 'node:crypto';
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
/** El `organizationName` del subject, o null si no lo lleva. */
export function organizationNameOf(pem) {
  try {
    return new x509.Name(new x509.X509Certificate(pem).subject).getField('O')[0] ?? null;
  } catch {
    return null;
  }
}

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
  const spec = signerRole(role);
  if (!spec) {
    throw new OpError(`rol desconocido: ${role}`, [`usa uno de: ${Object.keys(SIGNER_ROLES).join(', ')}`]);
  }
  // Sin emisor sale autofirmado, que es legitimo en las listas que publican el
  // certificado firmante: alli el ancla ES este certificado. Con emisor cuelga
  // de esa CA, que es lo que hace falta cuando la lista publica la CA (anexo F)
  // o cuando se quiere poder rotar la hoja sin reemitir la lista.
  if (!issuer && spec.requiresCa) {
    throw new OpError(`${spec.requiresCa}`, ['emite antes la CA con mint-ca y pasala como emisor']);
  }
  let ca = null;
  if (issuer) {
    const stored = await loadKey(store, issuer);
    const issuerCert = new x509.X509Certificate(stored.crt[0]);
    if (!issuerCert.getExtension('2.5.29.19')?.ca) {
      throw new OpError(`"${issuer}" no es una CA: no puede emitir un firmante`);
    }
    const caKey = await crypto.subtle.importKey('jwk', stored.key, P256, true, ['sign']);
    ca = { keys: { privateKey: caKey }, cert: issuerCert, pem: stored.crt[0] };
  }

  const material = await mintRoleSigner(crypto, ca, { role, subject, validityDays });
  await saveKeyChain(store, crypto, name, material);
  return { name, subject: material.cert.subject, role, issuer: issuer ?? null, spec,
    selfSigned: material.selfSigned };
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
  const naming = assertIdentityNaming(state, { subjectOf: organizationNameOf });
  const problems = [...assertLote(lote, state), ...naming.errors];
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
    entities: check.entities, url: state.url, nonNormative: profile?.nonNormative,
    warnings: [...naming.warnings, ...staleRevocationFields(state)] };
}

/** Cambia una posicion de la status list. NO publica: hay que reemitir. */
export async function setStatus(store, { id, idx, status, note }) {
  if (!(status in STATUS_BY_NAME)) throw new OpError(`estado desconocido: ${status}`);
  const state = await loadDoc(store, id);
  const positions = positionsOf(state);
  positions[idx] = {
    ...(positions[idx] ?? {}),
    status,
    ...(note ? { note } : {}),
    changedAt: new Date().toISOString(),
  };
  await store.docs.put(state.kind, id, setPositions(state, positions));
  return { id, idx, status, ocupante: positions[idx], pendingPublish: true };
}

/**
 * Crea una status list atada a quien emite los certificados que cubre.
 *
 * `issuerKey` no es un dato administrativo: es la clave que tendra que firmarla.
 * Quien emite un certificado es quien puede revocarlo, asi que la lista de
 * revocacion la firma el emisor de los WRPRC — no el operador de la lista de
 * confianza, que no tiene nada que ver con esos certificados.
 */
export async function createStatusList(store, { id, issuerKey, url, size = 1024, expiresInDays = 30 }) {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(id ?? '')) {
    throw new OpError('el identificador solo admite minusculas, digitos y guiones', [`recibido: "${id ?? ''}"`]);
  }
  if (await store.docs.get('*', id)) throw new OpError(`ya existe un documento con el id "${id}"`);
  const stored = await loadKey(store, issuerKey);
  if (!stored.crt?.length) throw new OpError(`la clave "${issuerKey}" no tiene certificado`);

  const doc = {
    kind: 'token-status-list',
    issuerKey,
    issuer: organizationNameOf(stored.crt[0]) ?? stored.subject ?? issuerKey,
    url: url?.trim() || null,
    bits: 1,
    size,
    expiresInDays,
    sequenceNumber: 0,
    entries: {},
  };
  if (!doc.url) throw new OpError('falta la URL por la que se publicara la lista');
  await store.docs.put('token-status-list', id, doc);
  return { id, issuerKey, issuer: doc.issuer, url: doc.url, size };
}

/** Ata una status list existente a su emisor. */
export async function setStatusIssuer(store, { id, issuerKey }) {
  const state = await loadDoc(store, id);
  if (state.kind !== 'token-status-list') throw new OpError(`"${id}" no es una status list`);
  const stored = await loadKey(store, issuerKey);
  if (!stored.crt?.length) throw new OpError(`la clave "${issuerKey}" no tiene certificado`);
  state.issuerKey = issuerKey;
  state.issuer = organizationNameOf(stored.crt[0]) ?? stored.subject ?? issuerKey;
  await store.docs.put(state.kind, id, state);
  return { id, issuerKey, issuer: state.issuer, pendientePublicar: true };
}

export async function buildStatusList(store, crypto, { id, signerName }) {
  const state = await loadDoc(store, id);
  // La firma la impone el documento, no quien pulsa el boton. Antes la consola
  // ofrecia los firmantes de listas (TLSO) — el operador del esquema de
  // confianza, que no emitio ninguno de estos certificados y por tanto no puede
  // revocarlos.
  if (state.issuerKey && signerName && signerName !== state.issuerKey) {
    throw new OpError(
      `"${id}" la firma su emisor, ${state.issuerKey}, no ${signerName}`,
      ['quien emite un certificado es quien puede revocarlo'],
    );
  }
  const firmante = state.issuerKey ?? signerName;
  if (!firmante) {
    throw new OpError(`"${id}" no tiene emisor asignado`, [
      'edita el documento y ponle issuerKey, o crea la lista desde /status',
    ]);
  }
  const { signer } = await importSigner(store, crypto, firmante);
  signerName = firmante;
  state.sequenceNumber += 1;
  const jwt = await signStatusListCompact(state, signer);
  const artifact = await store.artifacts.put({
    kind: 'status', id, sequence: state.sequenceNumber, signer: signerName,
    contentType: 'application/statuslist+jwt', body: jwt,
    nextUpdate: new Date(Date.now() + (state.expiresInDays ?? 30) * 86400000).toISOString(),
  });
  await store.docs.put(state.kind, id, state);
  const revoked = Object.values(positionsOf(state)).filter((e) => (e.status ?? 'valid') !== 'valid').length;
  return { id, sequence: state.sequenceNumber, artifact, size: state.size, revoked,
    url: state.url, signer: firmante, issuer: state.issuer ?? null };
}

export async function checkStatus(store, { id, idx, signerName }) {
  const state = await loadDoc(store, id).catch(() => null);
  const stored = await loadKey(store, signerName ?? state?.issuerKey);
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

  // El CLI no bloquea —en un laboratorio se montan escenarios rotos a
  // proposito— pero lo dice: la consola directamente no ofrece estas claves.
  const habilitadas = await enabledBy(store, 'EUWRPACProvidersList');
  const avisos = habilitadas.habilitadas.some((k) => k.name === caName)
    ? []
    : [`"${caName}" no esta publicada en ninguna lista de prestadores de access certificates: ` +
       'lo que salga no encadenara con nada'];

  const wrpac = await mintWrpac(crypto, ca, toWrpacSpec(registry, serviceId));
  const bad = assertWrpacProfile(wrpac.pem);
  if (bad.length) throw new OpError('el certificado no cumple el perfil de TS 119 411-8', bad);

  const name = keyName ?? `${registryId}-${serviceId}-access`;
  await saveKeyChain(store, crypto, name, wrpac);
  return { name, subject: wrpac.cert.subject, policy: wrpac.policy, policyOid: wrpac.policyOid, avisos };
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

  // Una posicion nueva en cada emision, y la anterior liberada. Lo pide la
  // 13.2: "every re-issued Referenced Token MUST have a fresh Status List
  // entry in order to prevent the index value from becoming a possible source
  // of correlation". Con la posicion fija, dos versiones del mismo WRPRC
  // comparten `uri`+`idx`, que es justo el par que la 12.5 llama trazable.
  let idx = sl?.indexByIntendedUse?.[useId];
  let liberada = null;
  if (sl?.listId) {
    if (idx !== undefined) {
      await releaseIndex(store, sl.listId, idx, `reemision de ${serviceId}/${useId}`);
      liberada = idx;
    }
    idx = await allocateIndex(store, sl.listId, { registry: registryId, service: serviceId, use: useId });
    registry.statusList.indexByIntendedUse = { ...(sl.indexByIntendedUse ?? {}), [useId]: idx };
    await store.docs.put(registry.kind ?? 'doc', registryId, registry);
  }

  const payload = buildWrprc(toWrprcInput(registry, serviceId, useId), {
    statusListUri: sl?.uri,
    statusListIdx: idx,
  });
  const bad = assertWrprc(payload);
  if (bad.length) throw new OpError('el payload no valida contra TS 119 475', bad);

  // Emitir contra una posicion revocada es legitimo tecnicamente y casi nunca
  // es lo que se queria: el certificado sale valido y cualquier consumidor que
  // mire el estado lo rechaza. Se avisa en vez de bloquear, porque reemitir
  // tras levantar la revocacion es un flujo real.
  const sl2 = await loadDoc(store, sl?.listId).catch(() => null);
  const estado = statusAt(positionsOf(sl2), idx);
  const avisos = estado !== 'valid'
    ? [`la posicion ${idx} de ${sl.listId} esta "${estado}": este WRPRC nace revocado`]
    : [];

  // El invariante de fondo: quien emite el certificado es quien lo revoca. Si
  // la lista a la que apunta la firma otro, el titular no puede revocarlo y
  // quien puede no lo emitio. Se avisa en vez de bloquear porque en un
  // laboratorio se montan a proposito escenarios asi.
  const hab = await enabledBy(store, 'EUWRPRCProvidersList');
  if (!hab.habilitadas.some((k) => k.name === signerName)) {
    avisos.push(
      `"${signerName}" no esta publicado en ninguna lista de prestadores de WRPRC: ` +
        'este certificado no encadenara con nada',
    );
  }
  if (sl2?.issuerKey && sl2.issuerKey !== signerName) {
    avisos.push(
      `este WRPRC lo firma ${signerName} pero su lista de revocacion (${sl.listId}) ` +
        `la firma ${sl2.issuerKey}: quien lo emite no es quien puede revocarlo`,
    );
  }

  const jwt = await signWrprcCompact(payload, signer, signerName);
  // El id lleva el registro delante: TS5 no exige que `serviceIdentifier` sea
  // unico entre relying parties, asi que dos RP con el mismo par
  // servicio/finalidad —el caso normal cuando las dos salen del mismo
  // esqueleto— se pisarian el certificado la una a la otra sin decir nada.
  // Releerlo antes de guardarlo, como las listas. Un artefacto que no se
  // verifica es un artefacto cuyo formato nadie comprueba: asi paso nueve dias
  // emitiendo WRPRC cuya firma no era base64url.
  const stored = await loadKey(store, signerName);
  await verifyWrprcCompact(jwt, stored.crt[0]);

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
    statusUri: sl?.uri, statusIndex: idx, liberada, avisos,
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
// ---------------------------------------------------------------------------
// Posiciones de una status list
//
// Habia DOS mapas sobre el mismo espacio de claves: `entries` con el estado de
// cada posicion y `assigned` con a quien se entrego. Se anadieron en momentos
// distintos —el estado primero, el libro de asignaciones despues, para impedir
// el reciclado— y nada los obligaba a estar separados: una posicion tiene un
// ocupante y un estado, no son dos cosas.
//
// Ahora es uno solo, `positions`. Los documentos antiguos se leen mezclando los
// dos y se reescriben unificados en cuanto algo los toca.
// ---------------------------------------------------------------------------

/** Las posiciones de una status list, vengan del formato nuevo o del viejo. */
export function positionsOf(doc) {
  if (doc?.positions) return { ...doc.positions };
  const out = {};
  for (const [idx, e] of Object.entries(doc?.assigned ?? {})) {
    out[idx] = { ...e };
  }
  for (const [idx, e] of Object.entries(doc?.entries ?? {})) {
    out[idx] = { ...(out[idx] ?? {}), ...e };
  }
  return out;
}

/** Escribe el mapa unificado y retira los dos antiguos. */
function setPositions(doc, positions) {
  doc.positions = positions;
  delete doc.entries;
  delete doc.assigned;
  return doc;
}

/** Estado efectivo de una posicion: sin marcar, valida. */
export const statusAt = (positions, idx) => positions?.[String(idx)]?.status ?? 'valid';

/**
 * Posiciones que NO se pueden entregar, por cualquiera de las tres razones.
 *
 * El libro de asignaciones vive en la propia status list (`assigned`), no en
 * los registros: una posicion sigue gastada cuando el registro que la tenia ya
 * no existe, y si el rastro viviera en el registro se iria con el.
 */
async function takenIndexes(store, listId) {
  const taken = new Set();
  const lista = await store.docs.get('*', listId).catch(() => null);
  const positions = positionsOf(lista);

  // 1. Toda posicion que figure en el mapa esta gastada, tenga ocupante vivo,
  //    liberado o solo un estado marcado. Una posicion no se recicla NUNCA:
  //    reutilizarla haria que un certificado nuevo heredase el rastro del
  //    viejo, y que quien guardase el veredicto antiguo se lo aplicase al
  //    nuevo titular.
  for (const idx of Object.keys(positions)) taken.add(Number(idx));

  // 3. Declaradas por algun registro. Es compatibilidad hacia atras: los
  //    registros anteriores al libro de asignaciones llevan la posicion dentro.
  for (const doc of await store.docs.list('*')) {
    if (!doc.walletRelyingParty || doc.statusList?.listId !== listId) continue;
    for (const idx of Object.values(doc.statusList.indexByIntendedUse ?? {})) taken.add(Number(idx));
  }
  return taken;
}

/**
 * Entrega una posicion libre, elegida AL AZAR.
 *
 * Secuencial filtra: la posicion dice cuantos certificados se habian emitido
 * antes que el tuyo, y dos posiciones contiguas delatan que se emitieron
 * seguidos. Como la lista se publica entera y es publica, eso lo lee
 * cualquiera. Al azar sobre un espacio reservado de golpe, la posicion no dice
 * nada — que es justo por lo que la lista se reserva entera.
 */
async function allocateIndex(store, listId, quien) {
  const lista = await loadDoc(store, listId);
  const size = lista.size ?? 1024;
  const taken = await takenIndexes(store, listId);
  const libres = size - taken.size;
  if (libres <= 0) {
    throw new OpError(`la lista "${listId}" no tiene posiciones libres`, [
      `${taken.size} de ${size} gastadas; las liberadas no se reciclan`,
    ]);
  }

  // Sortear entre las libres, no sortear y reintentar: con la lista casi llena
  // lo segundo degrada a un bucle sin cota.
  const disponibles = [];
  for (let i = 0; i < size; i += 1) if (!taken.has(i)) disponibles.push(i);
  const idx = disponibles[randomInt(disponibles.length)];

  const positions = positionsOf(lista);
  positions[idx] = { ...quien, status: 'valid', assignedAt: new Date().toISOString() };
  await store.docs.put(lista.kind, listId, setPositions(lista, positions));
  return idx;
}

/** Marca una posicion como liberada. Sigue gastada: no vuelve al sorteo. */
async function releaseIndex(store, listId, idx, motivo) {
  const lista = await store.docs.get('*', listId).catch(() => null);
  if (!lista) return false;
  const positions = positionsOf(lista);
  if (!positions[idx]) return false;
  positions[idx] = { ...positions[idx], releasedAt: new Date().toISOString(), motivo };
  await store.docs.put(lista.kind, listId, setPositions(lista, positions));
  return true;
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
    // Sin posicion: "Each Referenced Token is allocated an index **during
    // issuance**" (draft-ietf-oauth-status-list-21, seccion 1). Reservarla al
    // dar de alta la relying party la gastaba aunque no se emitiera nada, y
    // ademas impedia cumplir la 13.2 — que cada reemision lleve una nueva.
    statusList = { listId: statusListId, uri: list.url, indexByIntendedUse: {} };
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
  'la-revoca': 'se revoca con esta clave',
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
  const listId = doc.statusList?.listId;
  for (const [useId, idx] of Object.entries(doc.statusList?.indexByIntendedUse ?? {})) {
    if (listId && (await releaseIndex(store, listId, idx, `borrado el registro ${id}`))) {
      retirados.push(`posicion ${idx} de ${listId} liberada (no se reasigna)`);
    } else if (listId) {
      // Sin entrada en el libro es un registro anterior a el: se anota ahora
      // para que la posicion quede gastada igualmente.
      const lista = await store.docs.get('*', listId).catch(() => null);
      if (lista) {
        lista.assigned = lista.assigned ?? {};
        lista.assigned[idx] = {
          registry: id, use: useId, assignedAt: null,
          releasedAt: new Date().toISOString(), motivo: `borrado el registro ${id}`,
        };
        await store.docs.put(lista.kind, listId, lista);
        retirados.push(`posicion ${idx} de ${listId} marcada como gastada`);
      }
    }
  }
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

// ---------------------------------------------------------------------------
// Composicion de listas
//
// Poblar una lista era `add-provider` / `add-entity`: solo anadir, un elemento
// por comando, y para quitar algo habia que editar el JSON. El resultado
// practico es que las listas acumulaban lo sembrado sin que nadie lo mirara —
// que es como acaba habiendo un wallet provider por defecto que nadie creo.
//
// Esto lo convierte en lo que realmente es: elegir QUE contiene la lista, de
// una vez, entre lo que hay en el almacen.
// ---------------------------------------------------------------------------

/**
 * Que certificado del par clave+cadena publica una lista.
 *
 * Sale del perfil, no de una regla fija: TS 119 602 pide "el certificado que
 * verifica la firma que crea el proveedor", y eso es la hoja que firma en tres
 * de los cuatro anexos y la CA emisora en el de access certificates (anexo F,
 * donde lo que se firma es un X.509). Ver la nota en `packages/lote`.
 */
export function identityCertOf(doc, state) {
  if (state.kind === 'etsi-tl-xml') return doc.crt?.[0] ?? null;   // la AV TL publica el DS
  const ref = LIST_PROFILES[state.loteType]?.identityRef ?? 'signing';
  return (ref === 'issuing-ca' ? doc.crt?.at(-1) : doc.crt?.[0]) ?? null;
}

/**
 * Candidatos a entrar en una lista, con lo que hace falta para decidir:
 * que son, si su clave privada esta aqui, y si ya estan dentro.
 */
export async function listCandidates(store, id) {
  const state = await loadDoc(store, id);
  const { fingerprint } = await import('../../graph/src/index.mjs');
  const { describeKey } = await import('../../ca/src/index.mjs');
  const esAv = state.kind === 'etsi-tl-xml';
  const refCa = LIST_PROFILES[state.loteType]?.identityRef === 'issuing-ca';

  // La huella con la que se compara "ya esta dentro" tiene que ser la del
  // certificado que se guardaria al anadirlo, y cual es eso lo decide el perfil.
  const certOf = (doc) => identityCertOf(doc, state);

  const dentro = new Map();
  for (const p of state.providers ?? []) {
    for (const f of ['certPem', 'issuanceCertPem']) {
      if (p[f]) dentro.set(fingerprint(p[f]), p);
    }
  }

  const raw = store.rawKeys ?? store.keys;
  const porHuella = new Map();
  const vistos = new Set();
  for (const name of await store.keys.list()) {
    const doc = await raw.get(name);
    const cert = certOf(doc);
    if (!cert) continue;
    const fp = fingerprint(cert);
    vistos.add(fp);
    let d = {};
    try {
      d = describeKey(cert);
    } catch { /* se muestra igual, sin rol */ }
    const actual = dentro.get(fp);
    const fila = {
      keyName: name, fingerprint: fp, subject: doc.subject ?? null,
      role: d.role ?? null, ca: !!d.ca, expired: d.expired ?? null,
      dentro: !!actual, displayName: actual?.name ?? derivarNombre(doc.subject),
      cc: actual?.informationUri?.[0]?.slice(-2)?.toUpperCase() ?? null,
      tambien: [],
    };

    // Cuando la lista publica la CA emisora (anexo F), varias claves del
    // almacen —la CA y todo lo que cuelga de ella— acaban en la MISMA entrada,
    // asi que se agrupan. En las listas que publican el certificado firmante
    // cada clave es una entrada propia y no hay nada que agrupar.
    const previa = refCa ? porHuella.get(fp) : null;
    if (!previa) {
      porHuella.set(fp, fila);
      continue;
    }
    // Representa la fila la clave cuyo propio certificado ES el ancla.
    const esAncla = (doc2) => doc2.crt?.[0] === doc2.crt?.at(-1);
    if (!esAncla(await raw.get(previa.keyName)) && esAncla(doc)) {
      fila.tambien = [...previa.tambien, previa.keyName];
      porHuella.set(fp, fila);
    } else {
      previa.tambien.push(name);
    }
  }
  const candidatos = [...porHuella.values()];

  // Lo que la lista publica y no tiene clave aqui. Se ofrece para poder
  // QUITARLO, que es justo lo que hace falta con lo sembrado.
  const huerfanos = [];
  for (const [fp, p] of dentro) {
    if (vistos.has(fp)) continue;
    huerfanos.push({ fingerprint: fp, displayName: p.name, dentro: true, sinClave: true });
  }

  return {
    id, kind: state.kind, esAv, candidatos, huerfanos,
    entradas: (state.providers ?? []).length,
    identityHelp: esAv
      ? 'Una AV Trusted List publica el Document Signer, no la IACA, y cada entrada necesita el Estado miembro que la notifica.'
      : refCa
        ? 'TS 119 602 anexo F: esta lista publica el certificado que verifica la firma SOBRE el access certificate, es decir la CA emisora. Marca la CA, o una hoja que cuelgue de ella y se guardara su CA.'
        : 'TS 119 602: esta lista publica el certificado que verifica la firma que crea el proveedor, es decir el que FIRMA. Marca el certificado firmante, no su CA.',
  };
}

const derivarNombre = (subject) => {
  const o = /O=([^,]+)/.exec(subject ?? '')?.[1];
  const cn = /CN=([^,]+)/.exec(subject ?? '')?.[1];
  return (o ?? cn ?? '').trim() || null;
};

/**
 * Fija de una vez el contenido de una lista.
 *
 * `seleccion` son las entradas que la lista debe tener DESPUES; lo que no este
 * ahi, sale. Se reconstruye entera en vez de aplicar diferencias: una lista es
 * una declaracion de en quien se confia, y expresarla como "quita esto, anade
 * aquello" invita a que quede algo por el medio que nadie eligio.
 *
 * NO publica. Como todo cambio de estado, hace falta reemitir.
 */
export async function setProviders(store, { id, seleccion = [] }) {
  const state = await loadDoc(store, id);
  const esAv = state.kind === 'etsi-tl-xml';
  const { AV_TL_PROFILE } = await import('../../tl-xml/src/av-profile.mjs');
  const raw = store.rawKeys ?? store.keys;
  const previas = state.providers ?? [];
  const { fingerprint } = await import('../../graph/src/index.mjs');

  const providers = [];
  for (const sel of seleccion) {
    if (sel.fingerprint && !sel.keyName) {
      // Una entrada huerfana que se decide conservar: se copia tal cual, no se
      // puede reconstruir sin la clave.
      const previa = previas.find((p) =>
        [p.certPem, p.issuanceCertPem].some((c) => c && fingerprint(c) === sel.fingerprint));
      if (previa) providers.push(previa);
      continue;
    }
    const doc = await raw.get(sel.keyName);
    if (!doc?.crt?.length) throw new OpError(`la clave "${sel.keyName}" no tiene certificado`);
    const name = sel.displayName?.trim() || derivarNombre(doc.subject) || sel.keyName;

    if (esAv) {
      const cc = (sel.cc ?? '').toUpperCase();
      if (!/^[A-Z]{2}$/.test(cc)) {
        throw new OpError(`falta el Estado miembro que notifica a "${name}"`, [
          'la AV Trusted List lo exige: codigo ISO 3166-1 alpha-2',
        ]);
      }
      providers.push({
        name,
        serviceName: `${name} — AV attestation issuance`,
        informationUri: [AV_TL_PROFILE.paapInformationUriPrefix + cc.toLowerCase()],
        certPem: doc.crt[0],
      });
    } else {
      providers.push({ name, issuanceCertPem: identityCertOf(doc, state) });
    }
  }

  state.providers = providers;
  await store.docs.put(state.kind, id, state);
  return {
    id, entradas: providers.length, quitadas: previas.length - providers.length,
    nombres: providers.map((p) => p.name), pendientePublicar: true,
  };
}

/**
 * Claves habilitadas por una lista de prestadores.
 *
 * Un access certificate solo vale si su CA esta publicada en la lista de
 * prestadores de access certificates, y un WRPRC solo vale si su firmante esta
 * en la de prestadores de WRPRC. Es la misma comprobacion que hace un
 * verificador, hecha antes de emitir: si la clave no esta ahi, lo que salga no
 * encadena con nada y el fallo aparece al validar, no al firmar.
 *
 * Cuenta como habilitada la clave cuyo propio certificado esta publicado, y
 * tambien la que cuelga —por cadena— de algo publicado: en ambos casos un
 * verificador llega al ancla.
 */
export async function enabledBy(store, loteType) {
  const { fingerprint } = await import('../../graph/src/index.mjs');
  const publicadas = new Map();   // huella -> nombre de la entidad en la lista
  const listas = [];
  for (const doc of await store.docs.list('*')) {
    if (doc.kind !== 'lote-json' || doc.loteType !== loteType) continue;
    listas.push(doc.id);
    for (const p of doc.providers ?? []) {
      for (const f of ['issuanceCertPem', 'certPem']) {
        if (p[f]) publicadas.set(fingerprint(p[f]), p.name);
      }
    }
  }

  const raw = store.rawKeys ?? store.keys;
  const out = [];
  for (const name of await store.keys.list()) {
    const doc = await raw.get(name);
    const cadena = (doc?.crt ?? []).map(fingerprint);
    if (!cadena.length) continue;
    const propio = publicadas.has(cadena[0]);
    const porCadena = cadena.some((f) => publicadas.has(f));
    if (!porCadena) continue;
    out.push({
      name, subject: doc.subject ?? null,
      via: propio ? 'directo' : 'por cadena',
      entidad: publicadas.get(cadena.find((f) => publicadas.has(f))),
    });
  }
  return { listas, habilitadas: out, publicadas: publicadas.size };
}


/**
 * Los emisores de certificados de registro, con sus listas y sus posiciones.
 *
 * La pantalla se organiza por EMISOR y no por lista porque es lo que decide
 * todo lo demas: quien emite es quien revoca, y sus listas cuelgan de el. Una
 * lista huerfana —sin emisor asignado— aparece aparte, porque no se puede
 * emitir hasta atarla a uno.
 */
export async function wrprcIssuers(store) {
  const docs = await store.docs.list('*');
  const listas = docs.filter((d) => d.kind === 'token-status-list');
  const registros = docs.filter((d) => d.walletRelyingParty);

  // De que WRPRC es cada posicion: se resuelve una vez y se reparte.
  const emitidos = new Map();   // `${listId}#${idx}` -> datos del certificado
  for (const reg of registros) {
    const listId = reg.statusList?.listId;
    if (!listId) continue;
    for (const svc of reg.walletRelyingParty.services ?? []) {
      for (const u of svc.intendedUses ?? []) {
        const idx = reg.statusList.indexByIntendedUse?.[u.intendedUseIdentifier];
        if (idx === undefined) continue;
        const aid = wrprcArtifactId(reg.id, svc.serviceIdentifier, u.intendedUseIdentifier);
        emitidos.set(`${listId}#${idx}`, {
          artifactId: aid,
          rp: reg.id,
          legalName: reg.walletRelyingParty.legalName ?? reg.id,
          service: svc.serviceIdentifier,
          use: u.intendedUseIdentifier,
          publicado: !!(await store.artifacts.latest('wrprc', aid)),
        });
      }
    }
  }

  const raw = store.rawKeys ?? store.keys;
  const porEmisor = new Map();
  const huerfanas = [];

  for (const doc of listas) {
    const positions = positionsOf(doc);
    const filas = Object.entries(positions)
      .map(([idx, p]) => ({
        idx: Number(idx),
        status: p.status ?? 'valid',
        note: p.note ?? null,
        releasedAt: p.releasedAt ?? null,
        motivo: p.motivo ?? null,
        // El ocupante vivo se resuelve contra el registro; si no lo hay, se
        // usa lo que quedo anotado en el libro al entregarla.
        cert: emitidos.get(`${doc.id}#${idx}`) ?? null,
        anotado: [p.registry, p.service, p.use].filter(Boolean).join(' / ') || null,
      }))
      .sort((a, b) => a.idx - b.idx);

    const lista = {
      id: doc.id, url: doc.url ?? null, size: doc.size ?? 0,
      posiciones: filas,
      enUso: filas.filter((f) => !f.releasedAt).length,
      revocadas: filas.filter((f) => f.status !== 'valid').length,
      published: await store.artifacts.latest('status', doc.id),
    };

    if (!doc.issuerKey) {
      huerfanas.push(lista);
      continue;
    }
    if (!porEmisor.has(doc.issuerKey)) {
      const k = await raw.get(doc.issuerKey).catch(() => null);
      porEmisor.set(doc.issuerKey, {
        key: doc.issuerKey,
        nombre: doc.issuer ?? null,
        subject: k?.subject ?? null,
        listas: [],
      });
    }
    porEmisor.get(doc.issuerKey).listas.push(lista);
  }

  // Emisores habilitados por la lista de prestadores que aun no tienen lista:
  // sin ella no pueden revocar nada de lo que emitan.
  const habilitados = (await enabledBy(store, 'EUWRPRCProvidersList')).habilitadas;
  for (const h of habilitados) {
    if (!porEmisor.has(h.name)) {
      porEmisor.set(h.name, { key: h.name, nombre: h.entidad, subject: h.subject, listas: [] });
    }
  }

  return { emisores: [...porEmisor.values()], huerfanas };
}
