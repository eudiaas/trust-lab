// Todo lo que firmamos tiene que poder verificarse.
//
// Existe por un fallo concreto: `signWRPRC` concatena lo que devuelve el
// signer detras del signing input, asi que espera la firma en base64url. Le
// pasabamos el Uint8Array, JavaScript lo convertia a texto al concatenar, y la
// firma salia como "241,5,101,54,…" — los bytes en decimal. El JWS no
// verificaba, y nadie se enteraba porque nada lo releia.
//
// La leccion no es "acuerdate de convertir": es que un artefacto firmado que no
// se verifica de vuelta es un artefacto cuyo formato nadie comprueba. Este
// fichero lo comprueba para los tres formatos compactos que emitimos.
import 'reflect-metadata';
import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import { importX509, jwtVerify } from 'jose';
import { mintCa, mintRoleSigner } from '../packages/ca/src/index.mjs';
import { inMemorySigner } from '../packages/signer/src/index.mjs';
import { buildWrprc, signWrprcCompact, verifyWrprcCompact } from '../packages/wrprc/src/index.mjs';
import { signStatusListCompact, readStatus } from '../packages/status/src/index.mjs';

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

let fallos = 0;
const check = (nombre, cond, detalle = '') => {
  if (cond) console.log(`  ok   ${nombre}`);
  else { fallos += 1; console.log(`  FALLO ${nombre} ${detalle}`); }
};

const BASE64URL = /^[A-Za-z0-9_-]+$/;

console.log('FIRMAS: todo lo emitido se relee\n');

const ca = await mintCa(crypto, { subject: 'C=ES, O=Lab, CN=CA' });
const hoja = await mintRoleSigner(crypto, ca, {
  role: 'wrprc', subject: 'C=ES, O=Lab, CN=Firmante',
});
const signer = inMemorySigner(hoja.keys.privateKey, hoja.chainPem, crypto);

// --- WRPRC ---------------------------------------------------------------
const payload = buildWrprc(
  {
    tradeName: 'Servicio', legalName: 'Lab S.L.', identifier: 'VATES-B1',
    country: 'ES', registryUri: 'https://ejemplo/registro',
    srvDescription: [{ lang: 'en', value: 'x' }],
    purpose: [{ lang: 'en', value: 'x' }],
    entitlements: ['https://uri.etsi.org/19475/Entitlement/Service_Provider'],
    privacyPolicy: 'https://ejemplo/privacidad', infoUri: 'https://ejemplo',
    supervisoryAuthority: { email: ['soporte@ejemplo.com'] },
    credentials: [{ format: 'mso_mdoc', meta: { doctype_value: 'eu.europa.ec.av.1' },
      claims: [{ path: ['eu.europa.ec.av.1', 'age_over_18'] }] }],
  },
  { statusListUri: 'https://ejemplo/status', statusListIdx: 7 },
);
const jwt = await signWrprcCompact(payload, signer, 'k');
const firmaWrprc = jwt.split('.')[2];

check('WRPRC: la firma es base64url', BASE64URL.test(firmaWrprc),
  `\n       empieza por "${firmaWrprc.slice(0, 24)}"`);
check('WRPRC: no son bytes en decimal', !/^\d+(,\d+)+$/.test(firmaWrprc));
try {
  await verifyWrprcCompact(jwt, hoja.pem);
  check('WRPRC: verifica contra el certificado del firmante', true);
} catch (e) {
  check('WRPRC: verifica contra el certificado del firmante', false, e.code ?? e.message);
}
try {
  const roto = `${jwt.split('.').slice(0, 2).join('.')}.${'A'.repeat(firmaWrprc.length)}`;
  await verifyWrprcCompact(roto, hoja.pem);
  check('WRPRC: una firma manipulada se rechaza', false, '¡la acepto!');
} catch {
  check('WRPRC: una firma manipulada se rechaza', true);
}

// --- status list ---------------------------------------------------------
const statusJwt = await signStatusListCompact(
  { url: 'https://ejemplo/status', size: 64, bits: 1, entries: { 7: { status: 'invalid' } },
    issuer: 'Lab S.L.', expiresInDays: 30 },
  signer,
);
const firmaStatus = statusJwt.split('.')[2];
check('status list: la firma es base64url', BASE64URL.test(firmaStatus),
  `\n       empieza por "${firmaStatus.slice(0, 24)}"`);
try {
  const r = await readStatus(statusJwt, hoja.pem, 7);
  check('status list: verifica y lee la posicion', r.status === 'invalid', `→ ${r.status}`);
  check('status list: lleva el iss del emisor', r.iss === 'Lab S.L.', `→ ${r.iss}`);
} catch (e) {
  check('status list: verifica y lee la posicion', false, e.code ?? e.message);
}

// --- que jose acepte el WRPRC con la cadena completa ---------------------
try {
  await jwtVerify(jwt, await importX509(hoja.pem, 'ES256'), { clockTolerance: 300 });
  check('WRPRC: jose lo acepta como JWS estandar', true);
} catch (e) {
  check('WRPRC: jose lo acepta como JWS estandar', false, e.code ?? e.message);
}

console.log(fallos ? `\n${fallos} FALLO(S)` : '\nTODO OK');
process.exit(fallos ? 1 : 0);
