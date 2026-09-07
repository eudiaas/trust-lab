// Las operaciones. Ni imprimen ni renderizan: reciben el almacen y devuelven
// un resultado.
//
// Existe porque hay dos frontales —el CLI y la consola— y las operaciones no
// pueden vivir dos veces. Es el mismo problema que este proyecto lleva
// documentando toda la sesion en otros sitios (la logica del fallback AV
// duplicada en espuni, el vocabulario de la norma copiado a mano): dos copias
// de una regla acaban divergiendo, y la que diverge en una fabrica de
// certificados no se nota hasta que una wallet dice que no.
import { mintCa, mintLeaf, mintTlSigner, assertTlsoProfile } from '../../ca/src/index.mjs';
import { mintWrpac, assertWrpacProfile } from '../../ca/src/wrpac.mjs';
import { inMemorySigner } from '../../signer/src/index.mjs';
import { buildTrustedListXml, signTrustedListXml, assertAnnexB } from '../../tl-xml/src/index.mjs';
import { AV_TL_PROFILE, assertAvProfile } from '../../tl-xml/src/av-profile.mjs';
import { buildLote, signLoteCompact, verifyLoteCompact, assertLote, LIST_PROFILES } from '../../lote/src/index.mjs';
import { buildWrprc, signWrprcCompact, assertWrprc, decodeWRPRC, detectEdition, droppedByEdition } from '../../wrprc/src/index.mjs';
import { assertRegistry, toWrpacSpec, toWrprcInput } from '../../registry/src/index.mjs';
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
    kind: 'lists', id, sequence: state.sequenceNumber,
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
    kind: 'lote', id, sequence: state.sequenceNumber,
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
    kind: 'status', id, sequence: state.sequenceNumber,
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
  const artifact = await store.artifacts.put({
    kind: 'wrprc', id: `${serviceId}-${useId}`, sequence: Math.floor(Date.now() / 1000),
    contentType: 'application/jwt', body: jwt,
  });

  const back = decodeWRPRC(jwt);
  return {
    id: `${serviceId}-${useId}`, artifact,
    subject: payload.sub_ln ?? payload.name,
    entitlements: payload.entitlements.length,
    edition: detectEdition(back.header ?? {}, back.payload ?? back),
    statusUri: sl?.uri, statusIndex: idx,
    dropped: droppedByEdition(registry),
  };
}
