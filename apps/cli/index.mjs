#!/usr/bin/env node
// trustlab — frontal de linea de comandos. Solo parsea argumentos e imprime:
// las operaciones viven en `packages/ops`, compartidas con la consola web.
import 'reflect-metadata';
import { dirname, join } from 'node:path';
import { Crypto } from '@peculiar/webcrypto';
import { cryptoProvider } from '@peculiar/x509';
import { openStore } from '../../packages/store/src/index.mjs';
import * as ops from '../../packages/ops/src/index.mjs';
import { LIST_PROFILES } from '../../packages/lote/src/index.mjs';

const crypto = new Crypto();
// @peculiar/x509 mantiene su motor en un registro global: la capa impura (este
// CLI) es quien lo fija, para que los paquetes sigan sin estado global.
cryptoProvider.set(crypto);
const ROOT = join(dirname(new URL(import.meta.url).pathname), '../..');

let store;

/** Acepta tanto `espuni-rp` como `state/espuni-rp.json`: el id es lo que cuenta. */
const docId = (ref) => ref.replace(/^state\//, '').replace(/\.json$/, '');

const where = (r) => r.artifact?.path ?? `${store.kind}:${r.artifact?.kind}/${r.id}#${r.sequence}`;

const cmds = {
  // trustlab mint-ca <nombre> "<DN>"
  async 'mint-ca'([name, subject]) {
    const r = await ops.mintKey(store, crypto, { name, subject });
    console.log(`CA ${r.name}: ${r.subject}`);
  },

  // trustlab mint-leaf <nombre-ca> <nombre-hoja> "<DN>"
  async 'mint-leaf'([issuer, name, subject]) {
    const r = await ops.mintKey(store, crypto, { name, subject, issuer });
    console.log(`hoja ${r.name}: ${r.subject}`);
  },

  // trustlab mint-tl-signer <nombre> <esquema>
  async 'mint-tl-signer'([name, schemeId]) {
    const r = await ops.mintTlso(store, crypto, { name, schemeId: docId(schemeId) });
    console.log(`TLSO ${r.name}: ${r.subject}`);
    console.log('  perfil 5.7.1 (TS 119 612) · OK');
    for (const w of r.warnings) console.warn('  ⚠ ' + w);
  },

  // trustlab mint-wrpac <ca> <registro> <servicio> [nombre]
  async 'mint-wrpac'([caName, registryRef, serviceId, keyName]) {
    const r = await ops.issueWrpac(store, crypto, {
      registryId: docId(registryRef), serviceId, caName, keyName,
    });
    console.log(`WRPAC ${r.name}: ${r.subject}`);
    console.log(`  politica ${r.policy} (${r.policyOid}) · perfil 6.6.1 · OK`);
  },

  // trustlab add-provider <estado> <clave> "<nombre>" <CC>
  async 'add-provider'([stateId, keyName, displayName, cc]) {
    if (!/^[A-Z]{2}$/.test(cc ?? '')) throw new Error('falta el codigo ISO 3166-1 alpha-2 del Estado miembro del PAAP');
    const { AV_TL_PROFILE } = await import('../../packages/tl-xml/src/av-profile.mjs');
    const state = await store.docs.get('*', docId(stateId));
    const key = await store.keys.get(keyName);
    state.providers.push({
      name: displayName,
      serviceName: `${displayName} — AV attestation issuance`,
      informationUri: [AV_TL_PROFILE.paapInformationUriPrefix + cc.toLowerCase()],
      certPem: key.crt[0],
    });
    await store.docs.put(state.kind, docId(stateId), state);
    console.log(`anadido ${displayName} a ${stateId} (${state.providers.length} en total)`);
  },

  // trustlab add-entity <estado> <clave-emision> "<nombre>" [clave-revocacion]
  async 'add-entity'([stateId, issuanceKey, displayName, revocationKey]) {
    const state = await store.docs.get('*', docId(stateId));
    const issuance = await store.keys.get(issuanceKey);
    const revocation = revocationKey ? await store.keys.get(revocationKey) : null;
    state.providers.push({
      name: displayName,
      issuanceCertPem: issuance.crt.at(-1),   // el ancla: la raiz, no la hoja
      ...(revocation ? { revocationCertPem: revocation.crt.at(-1) } : {}),
    });
    await store.docs.put(state.kind, docId(stateId), state);
    console.log(`anadido ${displayName} a ${stateId} (${state.providers.length} en total)`);
  },

  // trustlab build-list <estado> <firmante>
  async 'build-list'([stateId, signerName]) {
    const r = await ops.buildAvList(store, crypto, { id: docId(stateId), signerName });
    console.log(`lista ${r.id} #${r.sequence} → ${where(r)}`);
    console.log('  Annex B (TS 119 612 v2.4.1) · OK');
    console.log('  perfil AV TL (CE, tablas I.1–I.3) · OK');
    for (const w of r.warnings) console.log('  ⚠ ' + w);
    console.log(`  verificada con @owf/eudi-tl · nextUpdate ${r.nextUpdate} · ${r.anchors} ancla(s)`);
    console.log(`  publicar en: ${r.url}`);
  },

  // trustlab build-lote <estado> <firmante>
  async 'build-lote'([stateId, signerName]) {
    const r = await ops.buildLoteList(store, crypto, { id: docId(stateId), signerName });
    const doc = await store.docs.get('*', docId(stateId));
    const profile = LIST_PROFILES[doc.loteType];
    console.log(`lista ${r.id} #${r.sequence} → ${where(r)}`);
    console.log(`  perfil ${doc.loteType} · tipos de servicio ${profile?.svc}/{Issuance,Revocation}`);
    if (r.nonNormative) console.log(`  ⚠ ${r.nonNormative}`);
    console.log(`  JWS verificado · nextUpdate ${r.nextUpdate} · ${r.entities} entidad(es)`);
    console.log(`  publicar en: ${r.url}`);
  },

  // trustlab issue-wrprc <registro> <servicio> <finalidad> <firmante>
  async 'issue-wrprc'([registryRef, serviceId, useId, signerName]) {
    const r = await ops.issueWrprc(store, crypto, {
      registryId: docId(registryRef), serviceId, useId, signerName,
    });
    console.log(`WRPRC ${r.id} → ${r.artifact?.path ?? `${store.kind}:wrprc/${r.id}`}`);
    console.log(`  sujeto ${r.subject} · ${r.entitlements} entitlement(s)`);
    console.log(`  edicion detectada al releerlo: ${r.edition}`);
    if (r.statusIndex !== undefined) console.log(`  revocable en ${r.statusUri} posicion ${r.statusIndex}`);
    for (const d of r.dropped) console.log(`  ⚠ no viaja en el certificado: ${d}`);
  },

  // trustlab status-set <estado> <posicion> <valid|invalid|suspended> ["motivo"]
  async 'status-set'([stateId, idx, status, note]) {
    const r = await ops.setStatus(store, { id: docId(stateId), idx, status, note });
    console.log(`posicion ${r.idx} → ${r.status}${note ? ` (${note})` : ''}`);
    console.log('  pendiente de reemitir la lista para que el cambio se publique');
  },

  // trustlab status-build <estado> <firmante>
  async 'status-build'([stateId, signerName]) {
    const r = await ops.buildStatusList(store, crypto, { id: docId(stateId), signerName });
    console.log(`status list ${r.id} #${r.sequence} → ${where(r)}`);
    console.log(`  ${r.size} posiciones · ${r.revoked} no valida(s)`);
    console.log(`  servir con Content-Type: application/statuslist+jwt en ${r.url}`);
  },

  // trustlab status-check <estado> <posicion> <firmante>
  async 'status-check'([stateId, idx, signerName]) {
    const r = await ops.checkStatus(store, { id: docId(stateId), idx, signerName });
    console.log(`posicion ${idx} de ${r.sub} → ${r.status}`);
  },

  // trustlab export-key <nombre> [chain|bundle|key|jwk] [destino]
  async 'export-key'([name, form = 'chain', dest]) {
    const r = await ops.exportKey(store, crypto, { name, form });
    await write(r, dest);
  },

  // trustlab export <tipo> <id> [destino]   (tipo: wrprc|lists|lote|status)
  async export([kind, id, dest]) {
    const r = await ops.exportArtifact(store, { kind, id: docId(id ?? '') });
    await write(r, dest);
  },
};

/** A fichero si dan destino, a stdout si no. El secreto nunca se anuncia solo. */
async function write(r, dest) {
  if (!dest) {
    process.stdout.write(r.body.endsWith('\n') ? r.body : r.body + '\n');
    if (r.secret) console.error('⚠ contiene la clave privada');
    return;
  }
  const { writeFile, mkdir } = await import('node:fs/promises');
  const { dirname: dn } = await import('node:path');
  const out = dest.endsWith('/') ? join(dest, r.filename) : dest;
  await mkdir(dn(out), { recursive: true });
  await writeFile(out, r.body, { mode: r.secret ? 0o600 : 0o644 });
  console.log(`${out}${r.secret ? ' (0600, contiene la clave privada)' : ''}`);
}

const [cmd, ...args] = process.argv.slice(2);
if (!cmds[cmd]) {
  console.error(`uso: trustlab <${Object.keys(cmds).join('|')}> ...`);
  process.exit(1);
}

try {
  store = await openStore({ root: ROOT });
  await cmds[cmd](args);
} catch (err) {
  // Un incumplimiento de perfil es un resultado esperado del CLI, no un fallo
  // del programa: se cuenta, no se vuelca la pila.
  console.error(`error: ${err.message}`);
  for (const d of err.details ?? []) console.error('  · ' + d);
  process.exitCode = 1;
} finally {
  await store?.close?.();
}
