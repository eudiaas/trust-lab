#!/usr/bin/env node
// trustlab — el único sitio del repo que toca disco (contrato 1).
import 'reflect-metadata';
import { dirname, join } from 'node:path';
import { Crypto } from '@peculiar/webcrypto';
import { cryptoProvider } from '@peculiar/x509';
import { TrustedListProfiles, loadTrustedList, getTrustAnchors } from '@owf/eudi-tl';
import { mintCa, mintLeaf, mintTlSigner, assertTlsoProfile } from '../../packages/ca/src/index.mjs';
import { mintWrpac, assertWrpacProfile, WRPAC_POLICY } from '../../packages/ca/src/wrpac.mjs';
import { buildWrprc, signWrprcCompact, assertWrprc, decodeWRPRC, detectEdition, droppedByEdition } from '../../packages/wrprc/src/index.mjs';
import { assertRegistry, toWrpacSpec, toWrprcInput } from '../../packages/registry/src/index.mjs';
import { signStatusListCompact, readStatus, STATUS_BY_NAME } from '../../packages/status/src/index.mjs';
import { fileStore, sqlStore, pgQuery, encryptedKeys } from '../../packages/store/src/index.mjs';
import { inMemorySigner } from '../../packages/signer/src/index.mjs';
import { buildTrustedListXml, signTrustedListXml, assertAnnexB } from '../../packages/tl-xml/src/index.mjs';
import { AV_TL_PROFILE, assertAvProfile } from '../../packages/tl-xml/src/av-profile.mjs';
import { buildLote, signLoteCompact, verifyLoteCompact, assertLote, LIST_PROFILES } from '../../packages/lote/src/index.mjs';

const crypto = new Crypto();
// @peculiar/x509 mantiene su motor en un registro global: la capa impura (este
// CLI) es quien lo fija, para que los paquetes sigan sin estado global.
cryptoProvider.set(crypto);
const ROOT = join(dirname(new URL(import.meta.url).pathname), '../..');

/**
 * El almacen sale del entorno: con DATABASE_URL, Postgres; sin ella, los
 * ficheros de siempre. El CLI no sabe cual esta usando, que es justo lo que
 * permite que el servicio y el CLI compartan estado sin duplicar logica.
 *
 * El cifrado del material de clave es OBLIGATORIO en SQL —una base de datos se
 * comparte y se respalda— y opcional en fichero, donde el material no sale de
 * la maquina del operador. En los dos casos, si se pide cifrado y no hay clave,
 * se falla en vez de guardar en claro.
 */
async function openStore() {
  // PGlite: Postgres compilado a WASM, sin servidor. Es el mismo SQL que
  // Railway, asi que el camino SQL se puede ejercitar entero en local y en CI
  // sin levantar nada — y sin que sea "otro motor" con otras reglas.
  if (process.env.TRUST_LAB_PGLITE) {
    const { PGlite } = await import('@electric-sql/pglite');
    const { pgliteQuery } = await import('../../packages/store/src/index.mjs');
    const db = await PGlite.create(process.env.TRUST_LAB_PGLITE);
    const store = sqlStore({ query: pgliteQuery(db), close: () => db.close() });
    await store.migrate();
    store.keys = encryptedKeys(store.keys, process.env.TRUST_LAB_KEY, { where: 'el almacen SQL' });
    return store;
  }

  const url = process.env.DATABASE_URL;
  if (!url) {
    const store = fileStore({ root: ROOT });
    if (process.env.TRUST_LAB_KEY) {
      store.keys = encryptedKeys(store.keys, process.env.TRUST_LAB_KEY, { where: 'el almacen de fichero' });
    }
    return store;
  }
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({ connectionString: url });
  const store = sqlStore({ query: pgQuery(pool), close: () => pool.end() });
  await store.migrate();
  store.keys = encryptedKeys(store.keys, process.env.TRUST_LAB_KEY, { where: 'el almacen SQL' });
  return store;
}

let store;   // se abre dentro del try de abajo: un fallo de configuracion
             // (p. ej. cifrado exigido sin clave) es un mensaje, no una pila.

/** Acepta tanto `espuni-rp` como `state/espuni-rp.json`: el id es lo que cuenta. */
const docId = (ref) => ref.replace(/^state\//, '').replace(/\.json$/, '');

async function loadDoc(ref) {
  const id = docId(ref);
  const doc = await store.docs.get('*', id);
  if (!doc) throw new Error(`no existe el documento "${id}" en el almacen (${store.kind})`);
  return doc;
}
const saveDoc = (ref, doc) => store.docs.put(doc.kind ?? 'doc', docId(ref), doc);
const loadKey = async (name) => {
  const doc = await store.keys.get(name);
  if (!doc) throw new Error(`no existe la clave "${name}" en el almacen (${store.kind})`);
  return doc;
};

async function exportKeyChain(name, material) {
  const jwk = await crypto.subtle.exportKey('jwk', material.keys.privateKey);
  await store.keys.put(name, {
    name,
    subject: material.cert.subject,
    key: jwk,
    crt: material.chainPem ?? [material.pem],
  });
  return material;
}

function assertRegistryOrExit(registry) {
  const problems = assertRegistry(registry);
  if (problems.length) {
    console.error('el registro no cumple el modelo de TS5/TS6:');
    for (const p of problems) console.error('  · ' + p);
    process.exit(1);
  }
}

const cmds = {
  // trustlab mint-ca <nombre> "<DN>"
  async 'mint-ca'([name, subject]) {
    const ca = await mintCa(crypto, { subject });
    await exportKeyChain(name, ca);
    console.log(`CA ${name}: ${ca.cert.subject}`);
  },

  // trustlab mint-tl-signer <nombre> <estado>
  //   El DN sale del estado de la lista: la cláusula 5.7.1 exige que Subject C
  //   y O coincidan con Scheme Territory y Scheme operator name.
  async 'mint-tl-signer'([name, stateId]) {
    const state = await loadDoc(stateId);
    const tlso = await mintTlSigner(crypto, {
      schemeOperatorName: state.schemeOperatorName,
      territory: state.territory,
      signerCountry: state.signerCountry,
      commonName: `${state.schemeOperatorName} TL Signer`,
    });
    const { errors, warnings } = assertTlsoProfile(tlso.pem, state);
    if (errors.length) {
      console.error('el certificado no cumple 5.7.1:');
      for (const p of errors) console.error('  · ' + p);
      process.exit(1);
    }
    for (const w of warnings) console.warn('  ⚠ ' + w);
    await exportKeyChain(name, tlso);
    console.log(`TLSO ${name}: ${tlso.cert.subject}`);
    console.log('  perfil 5.7.1 (TS 119 612) · OK');
  },

  // trustlab mint-leaf <nombre-ca> <nombre-hoja> "<DN>"
  async 'mint-leaf'([caName, name, subject]) {
    const stored = await loadKey(caName);
    const caKey = await crypto.subtle.importKey('jwk', stored.key,
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const { X509Certificate } = await import('@peculiar/x509');
    const ca = { keys: { privateKey: caKey }, cert: new X509Certificate(stored.crt[0]), pem: stored.crt[0] };
    const leaf = await mintLeaf(crypto, ca, { subject });
    await exportKeyChain(name, leaf);
    console.log(`hoja ${name}: ${leaf.cert.subject}`);
  },

  // trustlab add-provider <estado> <nombre-hoja> "<nombre visible>" <CC>
  async 'add-provider'([stateId, leafName, displayName, cc]) {
    const state = await loadDoc(stateId);
    const leaf = await loadKey(leafName);
    if (!/^[A-Z]{2}$/.test(cc ?? '')) throw new Error('falta el código ISO 3166-1 alpha-2 del Estado miembro del PAAP');
    state.providers.push({
      name: displayName,
      serviceName: `${displayName} — AV attestation issuance`,
      // Tabla I.2 del perfil AV: el URI lleva el código del EM donde está establecido.
      informationUri: [AV_TL_PROFILE.paapInformationUriPrefix + cc.toLowerCase()],
      certPem: leaf.crt[0],
    });
    await saveDoc(stateId, state);
    console.log(`añadido ${displayName} a ${stateId} (${state.providers.length} en total)`);
  },

  // trustlab mint-wrpac <nombre-ca> <nombre> <fichero-json-con-los-datos-del-RP>
  //   Access certificate de relying party con el perfil de TS 119 411-8.
  async 'mint-wrpac'([caName, name, registryPath]) {
    const registry = await loadDoc(registryPath);
    assertRegistryOrExit(registry);
    // GEN-6.6.1-10: los atributos se derivan del registro TS5, no se repiten.
    const serviceId = process.argv[6] ?? registry.walletRelyingParty.services[0].serviceIdentifier;
    const spec = toWrpacSpec(registry, serviceId);
    const stored = await loadKey(caName);
    const caKey = await crypto.subtle.importKey('jwk', stored.key,
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const { X509Certificate } = await import('@peculiar/x509');
    const ca = { keys: { privateKey: caKey }, cert: new X509Certificate(stored.crt[0]), pem: stored.crt[0] };

    const wrpac = await mintWrpac(crypto, ca, spec);
    const problems = assertWrpacProfile(wrpac.pem);
    if (problems.length) {
      console.error('el certificado no cumple el perfil de TS 119 411-8:');
      for (const p of problems) console.error('  · ' + p);
      process.exit(1);
    }
    await exportKeyChain(name, wrpac);
    console.log(`WRPAC ${name}: ${wrpac.cert.subject}`);
    console.log(`  política ${wrpac.policy} (${wrpac.policyOid}) · perfil 6.6.1 · OK`);
  },

  // trustlab issue-wrprc <registro> <servicio> <intended-use> <clave-firmante>
  //   Un WRPRC por intended use (TS5 §2.4.4: cardinalidad 1:1).
  async 'issue-wrprc'([registryPath, serviceId, useId, signerName]) {
    const registry = await loadDoc(registryPath);
    assertRegistryOrExit(registry);
    const stored = await loadKey(signerName);
    const key = await crypto.subtle.importKey('jwk', stored.key,
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);

    // El WRPRC apunta a su posición en la status list: es lo que permite
    // revocarlo después sin reemitir nada.
    const sl = registry.statusList;
    const idx = sl?.indexByIntendedUse?.[useId];
    const payload = buildWrprc(toWrprcInput(registry, serviceId, useId), {
      statusListUri: sl?.uri,
      statusListIdx: idx,
    });
    const problems = assertWrprc(payload);
    if (problems.length) {
      console.error('el payload no valida contra TS 119 475:');
      for (const p of problems) console.error('  · ' + p);
      process.exit(1);
    }

    const signer = inMemorySigner(key, stored.crt, crypto);
    const jwt = await signWrprcCompact(payload, signer, signerName);

    const artifact = await store.artifacts.put({
      kind: 'wrprc', id: `${serviceId}-${useId}`, sequence: Math.floor(Date.now() / 1000),
      contentType: 'application/jwt', body: jwt,
    });
    const outPath = artifact.path ?? `${store.kind}:wrprc/${serviceId}-${useId}`;

    const back = decodeWRPRC(jwt);
    console.log(`WRPRC ${serviceId}/${useId} → ${outPath}`);
    console.log(`  sujeto ${payload.sub?.legal_name ?? payload.name} · ${payload.entitlements.length} entitlement(s)`);
    console.log(`  edición detectada al releerlo: ${detectEdition(back.header ?? {}, back.payload ?? back)}`);
    if (idx !== undefined) console.log(`  revocable en ${sl.uri} posición ${idx}`);
    for (const d of droppedByEdition(registry)) console.log(`  ⚠ no viaja en el certificado: ${d}`);
  },

  // trustlab status-set <estado> <posición> <valid|invalid|suspended> ["motivo"]
  async 'status-set'([stateId, idx, status, note]) {
    if (!(status in STATUS_BY_NAME)) throw new Error(`estado desconocido: ${status}`);
    const state = await loadDoc(stateId);
    state.entries[idx] = { status, ...(note ? { note } : {}), changedAt: new Date().toISOString() };
    await saveDoc(stateId, state);
    console.log(`posición ${idx} → ${status}${note ? ` (${note})` : ''}`);
  },

  // trustlab status-build <estado> <clave-firmante>
  async 'status-build'([stateId, signerName]) {
    const state = await loadDoc(stateId);
    const stored = await loadKey(signerName);
    const key = await crypto.subtle.importKey('jwk', stored.key,
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);

    state.sequenceNumber += 1;
    const signer = inMemorySigner(key, stored.crt, crypto);
    const jwt = await signStatusListCompact(state, signer);

    const artifact = await store.artifacts.put({
      kind: 'status', id: stateId, sequence: state.sequenceNumber,
      contentType: 'application/statuslist+jwt', body: jwt,
      nextUpdate: new Date(Date.now() + (state.expiresInDays ?? 30) * 86400000).toISOString(),
    });
    await saveDoc(stateId, state);
    const outPath = artifact.path ?? `${store.kind}:status/${stateId}#${state.sequenceNumber}`;

    const revoked = Object.entries(state.entries).filter(([, e]) => e.status !== 'valid');
    console.log(`status list ${stateId} #${state.sequenceNumber} → ${outPath}`);
    console.log(`  ${state.size} posiciones · ${state.bits} bit(s) · ${revoked.length} no válida(s)`);
    console.log(`  servir con Content-Type: application/statuslist+jwt en ${state.url}`);
  },

  // trustlab status-check <estado> <posición> <clave-firmante>
  async 'status-check'([stateId, idx, signerName]) {
    const state = await loadDoc(stateId);
    const stored = await loadKey(signerName);
    const artifact = await store.artifacts.latest('status', stateId);
    if (!artifact) throw new Error(`no hay ninguna status list emitida para "${stateId}"`);
    const jwt = artifact.body;
    const r = await readStatus(jwt, stored.crt[0], Number(idx));
    console.log(`posición ${idx} de ${r.sub} → ${r.status}`);
  },

  // trustlab add-entity <estado> <nombre-clave-emisión> "<nombre visible>" [nombre-clave-revocación]
  //   Alta de una entidad en una lista LoTE.
  async 'add-entity'([stateId, issuanceKey, displayName, revocationKey]) {
    const state = await loadDoc(stateId);
    const issuance = await loadKey(issuanceKey);
    const revocation = revocationKey ? await loadKey(revocationKey) : null;
    state.providers.push({
      name: displayName,
      issuanceCertPem: issuance.crt.at(-1),      // el ancla: la raíz, no la hoja
      ...(revocation ? { revocationCertPem: revocation.crt.at(-1) } : {}),
    });
    await saveDoc(stateId, state);
    console.log(`añadido ${displayName} a ${stateId} (${state.providers.length} en total)`);
  },

  // trustlab build-lote <estado> <nombre-firmante>
  async 'build-lote'([stateId, signerName]) {
    const state = await loadDoc(stateId);
    const stored = await loadKey(signerName);
    const key = await crypto.subtle.importKey('jwk', stored.key,
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);

    state.sequenceNumber += 1;
    const lote = buildLote(state);

    const problems = assertLote(lote, state);
    if (problems.length) {
      console.error(`la lista no cumple TS 119 602 / el perfil ${state.loteType}:`);
      for (const p of problems) console.error('  · ' + p);
      process.exit(1);
    }

    const signer = inMemorySigner(key, stored.crt, crypto);
    const jws = await signLoteCompact(lote, signer, `${signerName}-${state.sequenceNumber}`);

    // Igual que en la lista XML: se verifica antes de guardar, así que nunca
    // se publica un artefacto que no valida.
    const check = await verifyLoteCompact(jws, stored.crt[0]);

    const artifact = await store.artifacts.put({
      kind: 'lote', id: stateId, sequence: state.sequenceNumber,
      contentType: 'application/jwt', body: jws,
      nextUpdate: check.nextUpdate,
    });
    await saveDoc(stateId, state);
    const outPath = artifact.path ?? `${store.kind}:lote/${stateId}#${state.sequenceNumber}`;

    const profile = LIST_PROFILES[state.loteType];
    console.log(`lista ${stateId} #${state.sequenceNumber} → ${outPath}`);
    console.log(`  perfil ${state.loteType} · tipos de servicio ${profile.svc}/{Issuance,Revocation}`);
    console.log(`  JWS verificado · nextUpdate ${check.nextUpdate} · ${check.entities} entidad(es)`);
    if (profile.nonNormative) console.log(`  ⚠ ${profile.nonNormative}`);
    console.log(`  publicar en: ${state.url}`);
  },

  // trustlab build-list <estado> <nombre-firmante>
  async 'build-list'([stateId, signerName]) {
    const state = await loadDoc(stateId);
    const stored = await loadKey(signerName);
    const key = await crypto.subtle.importKey('jwk', stored.key,
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);

    const tlso = assertTlsoProfile(stored.crt[0], state);
    if (tlso.errors.length) {
      console.error('el firmante no cumple el perfil TLSO de la cláusula 5.7.1:');
      for (const p of tlso.errors) console.error('  · ' + p);
      process.exit(1);
    }

    // 5.3.13 / tabla I.1: la lista se apunta a sí misma, con la identidad
    // digital de su propio firmante.
    state.pointerToSelf = { signerCertPem: stored.crt[0], mimeType: AV_TL_PROFILE.mimeType };

    const avProblems = assertAvProfile(state);
    if (avProblems.length && !state.allowDivergence) {
      console.error('el estado no cumple el perfil de la AV Trusted List:');
      for (const p of avProblems) console.error('  · ' + p);
      process.exit(1);
    }
    for (const w of avProblems) console.warn('  ⚠ divergencia del perfil AV: ' + w);

    state.sequenceNumber += 1;                       // contrato 3: estado explícito
    const profile = TrustedListProfiles[state.profile];
    const xml = buildTrustedListXml(state, profile);
    const signer = inMemorySigner(key, stored.crt, crypto);
    const signed = await signTrustedListXml(xml, signer, crypto);

    const annexB = assertAnnexB(signed);
    if (annexB.length) {
      console.error('la firma NO cumple el Annex B de TS 119 612:');
      for (const p of annexB) console.error('  · ' + p);
      process.exit(1);
    }

    // Verificación inmediata contra la MISMA librería que usan EUDIPLO y el
    // camino ZK: si aquí no pasa, no pasaría en producción tampoco.
    const anchorDer = new Uint8Array(
      Buffer.from(stored.crt[0].replace(/-----[^-]+-----|\s/g, ''), 'base64'),
    );
    const tl = await loadTrustedList(signed, { trustAnchors: [anchorDer] });
    const anchors = getTrustAnchors(tl, { serviceTypes: profile.serviceTypes });

    const artifact = await store.artifacts.put({
      kind: 'lists', id: stateId, sequence: state.sequenceNumber,
      contentType: 'application/vnd.etsi.tsl+xml', body: signed,
      nextUpdate: tl.nextUpdate,
    });
    await saveDoc(stateId, state);
    const outPath = artifact.path ?? `${store.kind}:lists/${stateId}#${state.sequenceNumber}`;

    console.log(`lista ${stateId} #${state.sequenceNumber} → ${outPath}`);
    console.log(`  Annex B (TS 119 612 v2.4.1) · OK`);
    console.log(`  perfil AV TL (CE, tablas I.1–I.3) · OK`);
    for (const w of tlso.warnings) console.log('  ⚠ ' + w);
    console.log(`  verificada con @owf/eudi-tl · nextUpdate ${tl.nextUpdate} · ${anchors.length} ancla(s)`);
    console.log(`  publicar en: ${state.url}`);
  },
};

const [cmd, ...args] = process.argv.slice(2);
if (!cmds[cmd]) {
  console.error(`uso: trustlab <${Object.keys(cmds).join('|')}> ...`);
  process.exit(1);
}
try {
  store = await openStore();
  await cmds[cmd](args);
} catch (err) {
  // Un incumplimiento de perfil es un resultado esperado del CLI, no un fallo
  // del programa: se cuenta, no se vuelca la pila.
  console.error(`error: ${err.message}`);
  process.exitCode = 1;
} finally {
  await store?.close?.();
}
