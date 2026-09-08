// Wallet-Relying Party Registration Certificates — ETSI TS 119 475.
//
// El WRPRC dice *en nombre de quién y para qué*; el WRPAC dice *quién hace la
// conexión*. GEN-6.6.1-10 de TS 119 411-8 los ata: los atributos del access
// certificate se derivan del registro que define TS 119 475 §5.1.2 — así que
// aquí los dos salen del mismo `state/<rp>.json` y no pueden derivar.
//
// La construcción, la firma JAdES B-B y la validación las hace
// @owf/eudi-wrprc, que implementa la **v1.2.1**. Ver EDITIONS más abajo: entre
// v1.1.1 y v1.2.1 cambiaron tres cosas que rompen la interoperabilidad, y
// ninguna es cosmética.
import { toBase64Url } from '../../signer/src/index.mjs';
import {
  wrprc,
  credential,
  signWRPRC,
  decodeWRPRC,
  validateWRPRCPayload,
  WRP_ENTITLEMENTS,
} from '@owf/eudi-wrprc';

/**
 * Qué cambió entre ediciones. Sirve para leer un WRPRC ajeno y saber contra
 * qué edición se emitió, que es la pregunta que aparece en cuanto hay dos
 * implementaciones en la sala.
 */
export const EDITIONS = {
  'v1.1.1': {
    published: '2025-10',
    header: ['typ', 'alg', 'x5c', 'b64', 'cty'],
    subject: { identifier: 'sub.id', legalName: 'sub.legal_name', givenName: 'sub.given_name' },
    serviceDescription: 'service',
    supervisoryAuthority: { field: 'dpa', fields: ['name', 'country', 'email', 'phone', 'uri'] },
    credentialClaims: 'claims',
    intermediary: { field: 'act', subject: 'sub.id', name: 'sub.name' },
  },
  'v1.2.1': {
    published: '2026-03',
    // La tabla 5 pierde `b64` y `cty`: eran una lectura de ETSI TS 119 182-1
    // que no encajaba con JOSE (`cty` es un string en RFC 7515, y la tabla
    // pedía una lista con el valor "b64").
    header: ['typ', 'alg', 'x5c'],
    // El sujeto se aplana: `sub` pasa a ser el identificador semántico y el
    // nombre legal sale a `sub_ln`.
    subject: { identifier: 'sub', legalName: 'sub_ln' },
    serviceDescription: 'srv_description',
    // La autoridad de control queda identificada SÓLO por contacto: name y
    // country desaparecen del esquema.
    supervisoryAuthority: { field: 'supervisory_authority', fields: ['email', 'phone', 'uri'] },
    credentialClaims: 'claim',
    intermediary: { field: 'intermediary', subject: 'sub', name: 'sname' },
  },
};

/** Detecta contra qué edición se emitió un WRPRC ya existente. */
export function detectEdition(header, payload) {
  const signals = [];
  if ('b64' in header || 'cty' in header) signals.push('v1.1.1');
  if (payload?.act) signals.push('v1.1.1');
  if (payload?.intermediary) signals.push('v1.2.1');
  const cred = payload?.credentials?.[0];
  if (cred && 'claims' in cred) signals.push('v1.1.1');
  if (cred && 'claim' in cred) signals.push('v1.2.1');
  const unique = [...new Set(signals)];
  return unique.length === 1 ? unique[0] : unique.length === 0 ? 'indeterminada' : `mezcla (${unique.join(' + ')})`;
}

const SA_FIELDS_V121 = EDITIONS['v1.2.1'].supervisoryAuthority.fields;

/**
 * Recorta la autoridad de control a lo que la edición vigente del certificado
 * admite, y aplana los arrays de TS5 (`email[]`, `phone[]`, `formURI[]`) al
 * escalar que espera el certificado.
 */
function pickSupervisoryAuthority(sa = {}) {
  const first = (v) => (Array.isArray(v) ? v[0] : v);
  const out = {};
  if (sa.email) out.email = first(sa.email);
  if (sa.phone) out.phone = first(sa.phone);
  if (sa.formURI ?? sa.uri) out.uri = first(sa.formURI ?? sa.uri);
  return out;
}

/**
 * Lo que el registro TS5 declara y el certificado v1.2.1 no puede transportar.
 *
 * No es una curiosidad: TS5 §2.4.7 marca `name` y `country` de la autoridad de
 * control como [1..1] **citando el requisito RPRC_12 del ARF**, que dice que
 * el registration certificate «shall contain the name and country of the
 * supervisory authority». La tabla de ETSI TS 119 475 v1.2.1 no los tiene: su
 * `supervisory_authority` es sólo `{ email, phone, uri }`. O sea que las dos
 * especificaciones se contradicen, y el certificado emitido cumple una a costa
 * de la otra. Se avisa en cada emisión en vez de descartarlo en silencio.
 */
export function droppedByEdition(registry) {
  const sa = registry.walletRelyingParty?.supervisoryAuthority ?? {};
  return ['name', 'country']
    .filter((k) => sa[k] !== undefined)
    .map((k) => `supervisoryAuthority.${k}="${sa[k]}" — TS5 §2.4.7 lo exige [1..1] citando ARF RPRC_12, pero la tabla de TS 119 475 v1.2.1 no lo transporta`);
}

/**
 * Construye el payload de UN intended use. La cardinalidad 1:1 entre WRPRC e
 * intended use la fija TS5 §2.4.4 ("issuance of RPRC is done separately for
 * each Intended use of a Wallet-Relying Party Service").
 *
 * Recibe la salida de `toWrprcInput` del paquete `registry`: la traducción
 * TS5 → ETSI vive allí, y aquí sólo se construye.
 */
export function buildWrprc(input, { issuedAt = new Date(), statusListUri, statusListIdx = 0 } = {}) {
  const b = wrprc()
    .name(input.tradeName)
    .legalName(input.legalName)
    .identifier(input.identifier)
    .country(input.country)
    .registryUri(input.registryUri)
    .privacyPolicy(input.privacyPolicy)
    .issuedAt(issuedAt);

  for (const d of input.srvDescription) b.serviceDescription(d.value, d.lang);
  for (const p of input.purpose) b.addPurpose(p.value, p.lang);
  for (const e of [...input.entitlements, ...(input.subEntitlements ?? [])]) b.addEntitlement(e);
  if (input.supportUri) b.supportUri(input.supportUri);
  if (input.infoUri) b.infoUri(input.infoUri);
  b.supervisoryAuthority(pickSupervisoryAuthority(input.supervisoryAuthority));

  for (const c of input.credentials) {
    const cb = credential().format(c.format);
    if (c.meta?.doctype_value) cb.mdocMeta(c.meta.doctype_value);
    else if (c.meta?.vct_values) cb.sdJwtMeta(c.meta.vct_values);
    // Selective disclosure: la lista de claims ES lo que el RP queda
    // autorizado a pedir. Es el control anti-overasking, no metadatos.
    for (const claim of c.claims ?? []) cb.addPathClaim(...claim.path);
    b.addCredential(cb.build());
  }

  if (statusListUri) b.status({ status_list: { idx: statusListIdx, uri: statusListUri } });
  if (input.intermediary) b.intermediary(input.intermediary);

  return b.build();
}

/**
 * Firma el WRPRC y devuelve el JWT compacto.
 *
 * GEN-5.2.1-04 (en las dos ediciones) exige JAdES B-B, y el perfil pide `iat`
 * en la cabecera como claimed signing time — lo pone `signWRPRC` vía
 * @owf/eudi-jades, no nosotros.
 */
export async function signWrprcCompact(payload, signer, keyId) {
  const signed = await signWRPRC({
    payload,
    algorithm: 'ES256',
    certificates: signer.certificateChain,
    keyId,
    // `signWRPRC` concatena lo que devuelva el signer detras del signing
    // input, asi que espera la firma YA en base64url —no bytes—, igual que
    // `signLoTE`. Devolviendo el Uint8Array tal cual, JavaScript lo convertia
    // a texto al concatenar y la firma salia como "241,5,101,54,…": los bytes
    // en decimal separados por comas. El JWS resultante no verifica.
    signer: async (data) => toBase64Url(await signer.sign(data)),
  });
  return typeof signed === 'string' ? signed : (signed.jwt ?? signed.jws ?? signed);
}

/**
 * Verificacion de vuelta, como la haria un consumidor.
 *
 * Existe porque su ausencia es la razon de que lo anterior durase: las listas
 * se relegan y se verifican antes de guardarse, y los WRPRC no. Un artefacto
 * que no se relee es un artefacto cuyo formato nadie comprueba.
 */
export async function verifyWrprcCompact(compactJwt, signerCertPem) {
  const { importX509, jwtVerify } = await import('jose');
  const key = await importX509(signerCertPem, 'ES256');
  const { payload, protectedHeader } = await jwtVerify(compactJwt, key, { clockTolerance: 300 });
  if (protectedHeader.typ !== 'rc-wrp+jwt') {
    throw new Error(`typ inesperado: ${protectedHeader.typ}`);
  }
  return { payload, header: protectedHeader };
}

/** Validación del payload + lectura de vuelta del token firmado. */
export function assertWrprc(payload) {
  const result = validateWRPRCPayload(payload);
  return result.valid ? [] : (result.errors ?? []).map((e) => e.message ?? String(e));
}

export { decodeWRPRC };
