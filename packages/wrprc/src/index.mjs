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

/** Recorta la autoridad de control a lo que la edición vigente admite. */
function pickSupervisoryAuthority(sa = {}) {
  return Object.fromEntries(Object.entries(sa).filter(([k]) => SA_FIELDS_V121.includes(k)));
}

/** Campos del registro que la edición vigente ya no transporta. */
export function droppedByEdition(registry) {
  return Object.keys(registry.supervisoryAuthority ?? {})
    .filter((k) => !SA_FIELDS_V121.includes(k))
    .map((k) => `supervisoryAuthority.${k} (existía en v1.1.1 como dpa.${k}, fuera del esquema en v1.2.1)`);
}

/** Construye el payload de un caso de uso del registro. Un WRPRC = un caso de uso. */
export function buildWrprc(registry, useCaseId, { issuedAt = new Date(), statusListUri, statusListIdx = 0 } = {}) {
  const uc = registry.useCases.find((u) => u.id === useCaseId);
  if (!uc) throw new Error(`caso de uso desconocido: ${useCaseId}`);
  const id = registry.identity;

  const b = wrprc()
    .name(id.tradeName ?? id.legalName)
    .legalName(id.legalName)
    .identifier(id.organizationIdentifier)
    .country(id.country)
    .registryUri(id.registryUri)
    .serviceDescription(uc.serviceDescription, 'en')
    .privacyPolicy(uc.privacyPolicy)
    .addPurpose(uc.purpose, 'en')
    // v1.2.1 identifica a la autoridad de control sólo por contacto. Pasarle
    // name/country no da error: los descarta en silencio, que es peor. Se
    // recortan aquí a propósito y se avisa arriba.
    .supervisoryAuthority(pickSupervisoryAuthority(registry.supervisoryAuthority))
    .issuedAt(issuedAt);

  for (const e of uc.entitlements) {
    const uri = WRP_ENTITLEMENTS[e] ?? e;
    b.addEntitlement(uri);
  }

  for (const c of uc.credentials) {
    const cb = credential().format(c.format);
    if (c.format === 'mso_mdoc') cb.mdocMeta(c.doctype);
    else cb.sdJwtMeta(c.vct);
    // Selective disclosure: cada claim es una ruta, y la lista es exactamente
    // lo que el RP queda autorizado a pedir. Es el control anti-overasking.
    for (const path of c.claims ?? []) cb.addPathClaim(...path);
    b.addCredential(cb.build());
  }

  if (statusListUri) b.status({ status_list: { idx: statusListIdx, uri: statusListUri } });
  if (uc.intermediary) b.intermediary(uc.intermediary);

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
    signer: (data) => signer.sign(data),
  });
  return typeof signed === 'string' ? signed : (signed.jwt ?? signed.jws ?? signed);
}

/** Validación del payload + lectura de vuelta del token firmado. */
export function assertWrprc(payload) {
  const result = validateWRPRCPayload(payload);
  return result.valid ? [] : (result.errors ?? []).map((e) => e.message ?? String(e));
}

export { decodeWRPRC };
