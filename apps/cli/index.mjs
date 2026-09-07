#!/usr/bin/env node
// trustlab — el único sitio del repo que toca disco (contrato 1).
import 'reflect-metadata';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Crypto } from '@peculiar/webcrypto';
import { cryptoProvider } from '@peculiar/x509';
import { TrustedListProfiles, loadTrustedList, getTrustAnchors } from '@owf/eudi-tl';
import { mintCa, mintLeaf, mintTlSigner, assertTlsoProfile } from '../../packages/ca/src/index.mjs';
import { inMemorySigner } from '../../packages/signer/src/index.mjs';
import { buildTrustedListXml, signTrustedListXml, assertAnnexB } from '../../packages/tl-xml/src/index.mjs';

const crypto = new Crypto();
// @peculiar/x509 mantiene su motor en un registro global: la capa impura (este
// CLI) es quien lo fija, para que los paquetes sigan sin estado global.
cryptoProvider.set(crypto);
const ROOT = join(dirname(new URL(import.meta.url).pathname), '../..');
const readJson = async (p) => JSON.parse(await readFile(p, 'utf8'));
const writeJson = (p, v) => writeFile(p, JSON.stringify(v, null, 2) + '\n');

async function exportKeyChain(name, material) {
  const jwk = await crypto.subtle.exportKey('jwk', material.keys.privateKey);
  await mkdir(join(ROOT, 'out/keys'), { recursive: true });
  await writeJson(join(ROOT, `out/keys/${name}.json`), {
    name,
    subject: material.cert.subject,
    key: jwk,
    crt: material.chainPem ?? [material.pem],
  });
  return material;
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
    const state = await readJson(join(ROOT, `state/${stateId}.json`));
    const tlso = await mintTlSigner(crypto, {
      schemeOperatorName: state.schemeOperatorName,
      territory: state.territory,
      commonName: `${state.schemeOperatorName} TL Signer`,
    });
    const problems = assertTlsoProfile(tlso.pem, state);
    if (problems.length) {
      console.error('el certificado no cumple 5.7.1:');
      for (const p of problems) console.error('  · ' + p);
      process.exit(1);
    }
    await exportKeyChain(name, tlso);
    console.log(`TLSO ${name}: ${tlso.cert.subject}`);
    console.log('  perfil 5.7.1 (TS 119 612) · OK');
  },

  // trustlab mint-leaf <nombre-ca> <nombre-hoja> "<DN>"
  async 'mint-leaf'([caName, name, subject]) {
    const stored = await readJson(join(ROOT, `out/keys/${caName}.json`));
    const caKey = await crypto.subtle.importKey('jwk', stored.key,
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const { X509Certificate } = await import('@peculiar/x509');
    const ca = { keys: { privateKey: caKey }, cert: new X509Certificate(stored.crt[0]), pem: stored.crt[0] };
    const leaf = await mintLeaf(crypto, ca, { subject });
    await exportKeyChain(name, leaf);
    console.log(`hoja ${name}: ${leaf.cert.subject}`);
  },

  // trustlab add-provider <estado> <nombre-hoja> "<nombre visible>"
  async 'add-provider'([stateId, leafName, displayName]) {
    const statePath = join(ROOT, `state/${stateId}.json`);
    const state = await readJson(statePath);
    const leaf = await readJson(join(ROOT, `out/keys/${leafName}.json`));
    state.providers.push({
      name: displayName, serviceName: `${displayName} — AV attestation issuance`,
      certPem: leaf.crt[0],
    });
    await writeJson(statePath, state);
    console.log(`añadido ${displayName} a ${stateId} (${state.providers.length} en total)`);
  },

  // trustlab build-list <estado> <nombre-firmante>
  async 'build-list'([stateId, signerName]) {
    const statePath = join(ROOT, `state/${stateId}.json`);
    const state = await readJson(statePath);
    const stored = await readJson(join(ROOT, `out/keys/${signerName}.json`));
    const key = await crypto.subtle.importKey('jwk', stored.key,
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);

    const tlsoProblems = assertTlsoProfile(stored.crt[0], state);
    if (tlsoProblems.length) {
      console.error('el firmante no cumple el perfil TLSO de la cláusula 5.7.1:');
      for (const p of tlsoProblems) console.error('  · ' + p);
      process.exit(1);
    }

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

    await mkdir(join(ROOT, 'out/lists'), { recursive: true });
    const outPath = join(ROOT, `out/lists/${stateId}.xml`);
    await writeFile(outPath, signed);
    await writeJson(statePath, state);

    // Verificación inmediata contra la MISMA librería que usan EUDIPLO y el
    // camino ZK: si aquí no pasa, no pasaría en producción tampoco.
    const anchorDer = new Uint8Array(
      Buffer.from(stored.crt[0].replace(/-----[^-]+-----|\s/g, ''), 'base64'),
    );
    const tl = await loadTrustedList(signed, { trustAnchors: [anchorDer] });
    const anchors = getTrustAnchors(tl, { serviceTypes: profile.serviceTypes });
    console.log(`lista ${stateId} #${state.sequenceNumber} → ${outPath}`);
    console.log(`  Annex B (TS 119 612) · OK`);
    console.log(`  verificada con @owf/eudi-tl · nextUpdate ${tl.nextUpdate} · ${anchors.length} ancla(s)`);
    console.log(`  publicar en: ${state.url}`);
  },
};

const [cmd, ...args] = process.argv.slice(2);
if (!cmds[cmd]) {
  console.error(`uso: trustlab <${Object.keys(cmds).join('|')}> ...`);
  process.exit(1);
}
await cmds[cmd](args);
