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

/** El grafo en Mermaid: para pegarlo donde haga falta sin instalar nada. */
function toMermaid(g) {
  const id = (s) => s.replace(/[^a-zA-Z0-9]/g, '_');
  const out = ['graph LR'];
  for (const n of g.nodes) {
    const shape = { list: ['[(', ')]'], key: ['[', ']'], rp: ['([', '])'], wrprc: ['>', ']'], orphan: ['{{', '}}'] }[n.type] ?? ['[', ']'];
    out.push(`  ${id(n.id)}${shape[0]}"${n.label}"${shape[1]}`);
  }
  for (const e of g.edges) {
    out.push(`  ${id(e.from)} -->|${e.type}${e.label ? ' ' + e.label : ''}| ${id(e.to)}`);
  }
  return out.join('\n');
}

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

  // trustlab mint-signer <ca|-> <nombre> <rol> "<DN>"
  //   roles: mdoc-ds | pid-ds | wrprc | wia | key-attestation
  //   con "-" como emisor sale autofirmado
  async 'mint-signer'([issuer, name, role, subject]) {
    const r = await ops.mintSigner(store, crypto, {
      issuer: issuer && issuer !== '-' ? issuer : undefined, name, role, subject,
    });
    console.log(`${r.spec.label} ${r.name}: ${r.subject}`);
    console.log(
      r.selfSigned
        ? `  autofirmado · publicar este mismo certificado en ${r.spec.lista}`
        : `  cuelga de ${r.issuer} · publicar ese ancla en ${r.spec.lista}`,
    );
    console.log(`  ${r.spec.nota}`);
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
    // Cual de los certificados del par se publica lo decide el perfil de la
    // lista (TS 119 602, anexos D-G), no una regla fija.
    state.providers.push({
      name: displayName,
      issuanceCertPem: ops.identityCertOf(issuance, state),
      ...(revocation ? { revocationCertPem: ops.identityCertOf(revocation, state) } : {}),
    });
    await store.docs.put(state.kind, docId(stateId), state);
    console.log(`anadido ${displayName} a ${stateId} (${state.providers.length} en total)`);
  },

  // trustlab remove-provider <estado> <indice|nombre>
  async 'remove-provider'([stateId, ref]) {
    const r = await ops.removeProvider(store, { id: docId(stateId), ref });
    console.log(`quitado "${r.removed}" de ${r.id} (${r.remaining} restante(s))`);
    console.log('  no publica: hay que reemitir la lista');
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
    for (const w of r.warnings ?? []) console.log(`  ⚠ ${w}`);
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
    if (r.statusIndex !== undefined) {
      console.log(`  revocable en ${r.statusUri} posicion ${r.statusIndex}` +
        (r.liberada !== null && r.liberada !== undefined ? ` (la ${r.liberada} queda gastada)` : ''));
    }
    for (const a of r.avisos ?? []) console.log(`  ⚠ ${a}`);
    for (const d of r.dropped) console.log(`  ⚠ no viaja en el certificado: ${d}`);
  },

  // trustlab status-set <estado> <posicion> <valid|invalid|suspended> ["motivo"]
  async 'status-set'([stateId, idx, status, note]) {
    const r = await ops.setStatus(store, { id: docId(stateId), idx, status, note });
    console.log(`posicion ${r.idx} → ${r.status}${note ? ` (${note})` : ''}`);
    console.log('  pendiente de reemitir la lista para que el cambio se publique');
  },

  // trustlab new-status-list <id> <clave-emisora> <url> [tamano]
  async 'new-status-list'([id, issuerKey, url, size]) {
    const r = await ops.createStatusList(store, { id, issuerKey, url, size: size ? Number(size) : undefined });
    console.log(`status list ${r.id} · emisor ${r.issuerKey} (${r.issuer})`);
    console.log(`  ${r.size} posiciones · se publicara en ${r.url}`);
    console.log('  la firma su emisor: quien emite un certificado es quien lo revoca');
  },

  // trustlab status-build <estado> [firmante]
  async 'status-build'([stateId, signerName]) {
    const r = await ops.buildStatusList(store, crypto, { id: docId(stateId), signerName });
    console.log(`status list ${r.id} #${r.sequence} → ${where(r)}`);
    console.log(`  firmada por ${r.signer}${r.issuer ? ` (${r.issuer})` : ''}`);
    console.log(`  ${r.size} posiciones · ${r.revoked} no valida(s)`);
    console.log(`  servir con Content-Type: application/statuslist+jwt en ${r.url}`);
  },

  // trustlab status-check <estado> <posicion> <firmante>
  async 'status-check'([stateId, idx, signerName]) {
    const r = await ops.checkStatus(store, { id: docId(stateId), idx, signerName });
    console.log(`posicion ${idx} de ${r.sub} → ${r.status}`);
  },

  // trustlab new-rp <id> "<razon social>" <valor-id> [pais] [lista-revocacion] [tipo-id]
  async 'new-rp'([id, legalName, identifierValue, country, statusListId, identifierType]) {
    const r = await ops.createRp(store, {
      id, legalName, identifierValue,
      country: country?.toUpperCase() ?? 'ES',
      statusListId: statusListId && statusListId !== '-' ? docId(statusListId) : undefined,
      ...(identifierType ? { identifierType } : {}),
    });
    console.log(`registro ${r.id}: ${r.legalName}`);
    if (r.statusList) console.log(`  se revocara en ${r.statusList.uri} (posicion al emitir)`);
    else console.log('  sin lista de revocacion: los WRPRC saldran sin `status`');
    console.log('  esqueleto valido; rellena los campos PENDIENTE antes de emitir nada');
  },

  // trustlab graph [mermaid]
  async graph([format]) {
    const { buildGraph, danglingChains } = await import('../../packages/graph/src/index.mjs');
    const g = await buildGraph(store);
    if (format === 'mermaid') {
      console.log(toMermaid(g));
      return;
    }
    for (const n of g.nodes.filter((x) => x.type === 'list')) {
      const firmante = g.edges.find((e) => e.from === n.id && e.type === 'firmada-por');
      console.log(`${n.label}  ${n.published ? '#' + n.published.sequence : '(sin publicar)'}`);
      if (firmante) console.log(`  firmada por ${firmante.to.replace('key:', '')}`);
      for (const e of g.edges.filter((x) => x.to === n.id && x.type === 'contenido-en')) {
        const from = g.nodes.find((x) => x.id === e.from);
        const huerfano = from?.type === 'orphan' ? '  ⚠ sin clave privada en el almacen' : '';
        console.log(`  contiene ${e.label ?? from?.label}${huerfano}`);
        for (const h of g.edges.filter((x) => x.to === e.from && x.type === 'emitido-por')) {
          console.log(`    └ emite ${h.from.replace('key:', '')}`);
        }
      }
    }
    const roto = danglingChains(g);
    if (roto.length) {
      console.log('\ncadenas que no llegan a ningun ancla:');
      for (const r of roto) console.log(`  ⚠ ${r.label}: ${r.why}`);
    }
  },

  // trustlab delete-key <nombre> [force]
  async 'delete-key'([name, force]) {
    const r = await ops.deleteKey(store, { name, force: force === 'force' });
    console.log(`borrada ${r.deleted}`);
    for (const b of r.broke) console.log(`  ⚠ rota: ${b}`);
  },

  // trustlab delete-rp <id> [force]
  async 'delete-rp'([id, force]) {
    const r = await ops.deleteRp(store, { id, force: force === 'force' });
    console.log(`borrado ${r.deleted}`);
    for (const x of r.retirados) console.log(`  retirado ${x}`);
  },

  // trustlab delete-wrprc <id>
  async 'delete-wrprc'([id]) {
    const r = await ops.deleteWrprc(store, { id });
    console.log(`borrado el WRPRC ${r.deleted} (#${r.sequence})`);
  },

  // trustlab unpublish <estado>
  async unpublish([stateId]) {
    const r = await ops.unpublish(store, { id: docId(stateId) });
    console.log(`retirada la version #${r.retirada} de ${r.id}`);
    console.log(`  ${r.url} deja de servirse hasta que se reemita`);
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
