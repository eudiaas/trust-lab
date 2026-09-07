#!/usr/bin/env node
// trustlab — el único sitio del repo que toca disco (contrato 1).
import 'reflect-metadata';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Crypto } from '@peculiar/webcrypto';
import { cryptoProvider } from '@peculiar/x509';
import { TrustedListProfiles, loadTrustedList, getTrustAnchors } from '@owf/eudi-tl';
import { mintCa, mintLeaf, mintTlSigner, assertTlsoProfile } from '../../packages/ca/src/index.mjs';
import { mintWrpac, assertWrpacProfile, WRPAC_POLICY } from '../../packages/ca/src/wrpac.mjs';
import { buildWrprc, signWrprcCompact, assertWrprc, decodeWRPRC, detectEdition, droppedByEdition } from '../../packages/wrprc/src/index.mjs';
import { inMemorySigner } from '../../packages/signer/src/index.mjs';
import { buildTrustedListXml, signTrustedListXml, assertAnnexB } from '../../packages/tl-xml/src/index.mjs';
import { AV_TL_PROFILE, assertAvProfile } from '../../packages/tl-xml/src/av-profile.mjs';
import { buildLote, signLoteCompact, verifyLoteCompact, assertLote, LIST_PROFILES } from '../../packages/lote/src/index.mjs';

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
    const stored = await readJson(join(ROOT, `out/keys/${caName}.json`));
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
    const statePath = join(ROOT, `state/${stateId}.json`);
    const state = await readJson(statePath);
    const leaf = await readJson(join(ROOT, `out/keys/${leafName}.json`));
    if (!/^[A-Z]{2}$/.test(cc ?? '')) throw new Error('falta el código ISO 3166-1 alpha-2 del Estado miembro del PAAP');
    state.providers.push({
      name: displayName,
      serviceName: `${displayName} — AV attestation issuance`,
      // Tabla I.2 del perfil AV: el URI lleva el código del EM donde está establecido.
      informationUri: [AV_TL_PROFILE.paapInformationUriPrefix + cc.toLowerCase()],
      certPem: leaf.crt[0],
    });
    await writeJson(statePath, state);
    console.log(`añadido ${displayName} a ${stateId} (${state.providers.length} en total)`);
  },

  // trustlab mint-wrpac <nombre-ca> <nombre> <fichero-json-con-los-datos-del-RP>
  //   Access certificate de relying party con el perfil de TS 119 411-8.
  async 'mint-wrpac'([caName, name, registryPath]) {
    const registry = await readJson(registryPath);
    // GEN-6.6.1-10: los atributos salen del registro, no de un fichero aparte.
    const spec = { ...registry.identity, ...registry.wrpac, organization: registry.identity.legalName };
    const stored = await readJson(join(ROOT, `out/keys/${caName}.json`));
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

  // trustlab issue-wrprc <fichero-registro> <caso-de-uso> <clave-firmante>
  //   Registration certificate para UN caso de uso (TS 119 475: cardinalidad 1:1).
  async 'issue-wrprc'([registryPath, useCaseId, signerName]) {
    const registry = await readJson(registryPath);
    const stored = await readJson(join(ROOT, `out/keys/${signerName}.json`));
    const key = await crypto.subtle.importKey('jwk', stored.key,
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);

    const payload = buildWrprc(registry, useCaseId, {
      statusListUri: registry.statusListUri,
    });
    const problems = assertWrprc(payload);
    if (problems.length) {
      console.error('el payload no valida contra TS 119 475:');
      for (const p of problems) console.error('  · ' + p);
      process.exit(1);
    }

    const signer = inMemorySigner(key, stored.crt, crypto);
    const jwt = await signWrprcCompact(payload, signer, signerName);

    await mkdir(join(ROOT, 'out/wrprc'), { recursive: true });
    const outPath = join(ROOT, `out/wrprc/${registry.identity.organizationIdentifier}-${useCaseId}.jwt`);
    await writeFile(outPath, jwt);

    const back = decodeWRPRC(jwt);
    console.log(`WRPRC ${useCaseId} → ${outPath}`);
    console.log(`  sujeto ${payload.sub?.legal_name ?? payload.name} · ${payload.entitlements.length} entitlement(s)`);
    console.log(`  edición detectada al releerlo: ${detectEdition(back.header ?? {}, back.payload ?? back)}`);
    for (const d of droppedByEdition(registry)) console.log(`  ⚠ no viaja en el certificado: ${d}`);
  },

  // trustlab add-entity <estado> <nombre-clave-emisión> "<nombre visible>" [nombre-clave-revocación]
  //   Alta de una entidad en una lista LoTE.
  async 'add-entity'([stateId, issuanceKey, displayName, revocationKey]) {
    const statePath = join(ROOT, `state/${stateId}.json`);
    const state = await readJson(statePath);
    const issuance = await readJson(join(ROOT, `out/keys/${issuanceKey}.json`));
    const revocation = revocationKey
      ? await readJson(join(ROOT, `out/keys/${revocationKey}.json`))
      : null;
    state.providers.push({
      name: displayName,
      issuanceCertPem: issuance.crt.at(-1),      // el ancla: la raíz, no la hoja
      ...(revocation ? { revocationCertPem: revocation.crt.at(-1) } : {}),
    });
    await writeJson(statePath, state);
    console.log(`añadido ${displayName} a ${stateId} (${state.providers.length} en total)`);
  },

  // trustlab build-lote <estado> <nombre-firmante>
  async 'build-lote'([stateId, signerName]) {
    const statePath = join(ROOT, `state/${stateId}.json`);
    const state = await readJson(statePath);
    const stored = await readJson(join(ROOT, `out/keys/${signerName}.json`));
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

    await mkdir(join(ROOT, 'out/lists'), { recursive: true });
    const outPath = join(ROOT, `out/lists/${stateId}.json`);
    await writeFile(outPath, jws);
    await writeJson(statePath, state);

    const check = await verifyLoteCompact(jws, stored.crt[0]);
    const profile = LIST_PROFILES[state.loteType];
    console.log(`lista ${stateId} #${state.sequenceNumber} → ${outPath}`);
    console.log(`  perfil ${state.loteType} · tipos de servicio ${profile.svc}/{Issuance,Revocation}`);
    console.log(`  JWS verificado · nextUpdate ${check.nextUpdate} · ${check.entities} entidad(es)`);
    if (profile.nonNormative) console.log(`  ⚠ ${profile.nonNormative}`);
    console.log(`  publicar en: ${state.url}`);
  },

  // trustlab build-list <estado> <nombre-firmante>
  async 'build-list'([stateId, signerName]) {
    const statePath = join(ROOT, `state/${stateId}.json`);
    const state = await readJson(statePath);
    const stored = await readJson(join(ROOT, `out/keys/${signerName}.json`));
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
  await cmds[cmd](args);
} catch (err) {
  // Un incumplimiento de perfil es un resultado esperado del CLI, no un fallo
  // del programa: se cuenta, no se vuelca la pila.
  console.error(`error: ${err.message}`);
  process.exit(1);
}
