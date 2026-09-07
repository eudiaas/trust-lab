// Listas LoTE — ETSI TS 119 602 v1.1.1 (2025-11), "List of Trusted Entities".
//
// Es el formato de las listas EUDI que NO son la de AV: PID providers, wallet
// providers, y —lo que desbloquea el banco de pruebas— proveedores de
// certificados de acceso (WRPAC) y de certificados de registro (WRPRC).
// JSON dentro de un JWS, no XML: aquí no hace falta XAdES.
//
// La construcción y la firma las hace @owf/eudi-lote; este paquete aporta el
// vocabulario de la norma, el mapeo tipo-de-lista → tipos-de-servicio, y las
// comprobaciones. Puro: sin I/O (contrato 1); la firma entra por `Signer`
// (contrato 2) — que encaja tal cual, porque `signLoTE` ya recibe un signer.
import {
  createLoTE,
  service,
  trustedEntity,
  signLoTE,
  validateLoTE,
  LoTEProfile,
} from '@owf/eudi-lote';
import { importX509, jwtVerify, decodeJwt } from 'jose';
import { pemToBase64Der, toBase64Url } from '../../signer/src/index.mjs';

/** Cláusula 6 y anexos de TS 119 602: tipos de servicio, por rol. */
export const SVC = {
  PID: 'http://uri.etsi.org/19602/SvcType/PID',
  WalletSolution: 'http://uri.etsi.org/19602/SvcType/WalletSolution',
  WRPAC: 'http://uri.etsi.org/19602/SvcType/WRPAC',
  WRPRC: 'http://uri.etsi.org/19602/SvcType/WRPRC',
  PubEAA: 'http://uri.etsi.org/19602/SvcType/PubEAA',
  Register: 'http://uri.etsi.org/19602/SvcType/Register',
};

/**
 * Qué tipo de servicio corresponde a cada tipo de lista.
 *
 * ⚠ `EUEAAProvidersList` → `SvcType/EAA/*` **no está en TS 119 602 v1.1.1**.
 * La norma define PID, WalletSolution, WRPAC, WRPRC, PubEAA y Register, y nada
 * más. Pero `@owf/eudi-lote` lo incluye como perfil y EUDIPLO lo cablea como
 * único tipo de servicio de sus listas gestionadas, así que se conserva por
 * interoperabilidad — marcado, no escondido.
 */
/**
 * Que certificado va en el `ServiceDigitalIdentity` de cada perfil.
 *
 * TS 119 602 no habla de anclas, ni de cadenas, ni de CA frente a hoja: esas
 * palabras no aparecen en la norma. Define la identidad digital por FUNCION
 * (clause 6.6.3 y anexos D-G): "one or more X.509 certificates that can be used
 * to verify the signature or seal created by the provider on [lo que emite]".
 *
 * Aplicado a cada anexo, eso da dos respuestas distintas:
 *
 * - `signing` — lo que verifica la firma es el certificado que FIRMA. Anexo D
 *   (el PID lo sella el Document Signer del proveedor), anexo E (los
 *   componentes del wallet unit los firma el wallet provider) y anexo G (el
 *   registration certificate es un JWS firmado por su emisor). Es tambien lo
 *   que hace la AV Trusted List, que publica el DS y no la IACA.
 * - `issuing-ca` — anexo F: lo que se verifica es la firma "on the access
 *   certificate", y un certificado X.509 lo firma su CA emisora. Ahi el
 *   certificado que hace falta es el de la CA.
 *
 * El campo `identityRef` de cada perfil dice cual, y de ahi sale que
 * certificado se guarda al anadir una entidad. Antes se guardaba SIEMPRE la
 * raiz de la cadena, que solo es correcto para el anexo F.
 */
export const LIST_PROFILES = {
  [LoTEProfile.EUPIDProvidersList]: {
    loteType: 'http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList',
    svc: SVC.PID,
    identityRef: 'signing', // anexo D: verifica el sello del proveedor sobre el PID
    statusDeterminationApproach: 'http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU',
    schemeTypeCommunityRules: 'http://uri.etsi.org/19602/PIDProviders/schemerules/EU',
  },
  [LoTEProfile.EUWalletProvidersList]: {
    loteType: 'http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList',
    svc: SVC.WalletSolution,
    identityRef: 'signing', // anexo E: autentica los componentes del wallet unit
    statusDeterminationApproach: 'http://uri.etsi.org/19602/WalletProvidersList/StatusDetn/EU',
    schemeTypeCommunityRules: 'http://uri.etsi.org/19602/WalletProvidersList/schemerules/EU',
  },
  [LoTEProfile.EUWRPACProvidersList]: {
    loteType: 'http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList',
    svc: SVC.WRPAC,
    identityRef: 'issuing-ca', // anexo F: verifica la firma SOBRE el access certificate
    statusDeterminationApproach: 'http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU',
    schemeTypeCommunityRules: 'http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU',
  },
  [LoTEProfile.EUWRPRCProvidersList]: {
    loteType: 'http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList',
    svc: SVC.WRPRC,
    identityRef: 'signing', // anexo G: verifica la firma del JWS del registration certificate
    // Sí, "WRPRCrovidersList": la errata está en la propia norma (le falta la
    // P). Se reproduce tal cual — un consumidor que la compare por igualdad
    // esperará la URI publicada, no la que nosotros creamos correcta.
    statusDeterminationApproach: 'http://uri.etsi.org/19602/WRPRCrovidersList/StatusDetn/EU',
    schemeTypeCommunityRules: 'http://uri.etsi.org/19602/WRPRCProvidersList/schemerules/EU',
  },
  [LoTEProfile.EUPubEAAProvidersList]: {
    loteType: 'http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList',
    svc: SVC.PubEAA,
    identityRef: 'signing', // anexo H
    namingMandatory: true, // anexo H: "shall have the organizationName ... shall strictly match"
    statusDeterminationApproach: 'http://uri.etsi.org/19602/PubEAAProvidersList/StatusDetn/EU',
    schemeTypeCommunityRules: 'http://uri.etsi.org/19602/PubEAAProvidersList/schemerules/EU',
    serviceStatuses: [
      'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified',
      'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn',
    ],
  },
  [LoTEProfile.EUEAAProvidersList]: {
    loteType: 'http://uri.etsi.org/19602/LoTEType/EUEAAProvidersList',
    svc: 'http://uri.etsi.org/19602/SvcType/EAA',
    nonNormative: 'SvcType/EAA no está definido en TS 119 602 v1.1.1',
  },
};

const iso = (d) => new Date(d).toISOString().replace(/\.\d+Z$/, 'Z');

/**
 * Construye el documento LoTE (sin firmar) desde el estado del entorno.
 *
 * Cada entidad lleva dos servicios —emisión y revocación— porque el modelo de
 * confianza los empareja: la lista de estado tiene que estar firmada por la
 * misma entidad que emitió lo que se revoca. Si un proveedor de laboratorio no
 * publica estado, se le pasa el mismo certificado en los dos: es explícito y no
 * finge una separación que no existe.
 */
export function buildLote(state, now = new Date()) {
  const profile = LIST_PROFILES[state.loteType];
  if (!profile) throw new Error(`tipo de lista desconocido: ${state.loteType}`);
  const lang = state.lang ?? 'en';

  const entities = state.providers.map((p) => {
    const issuance = service()
      .name(`${p.name} — issuance`, lang)
      .type(`${profile.svc}/Issuance`)
      .addCertificate(pemToBase64Der(p.issuanceCertPem));
    if (profile.serviceStatuses) issuance.status(p.status ?? profile.serviceStatuses[0], now);

    const revocation = service()
      .name(`${p.name} — revocation`, lang)
      .type(`${profile.svc}/Revocation`)
      .addCertificate(pemToBase64Der(p.revocationCertPem ?? p.issuanceCertPem));
    if (profile.serviceStatuses) revocation.status(p.status ?? profile.serviceStatuses[0], now);

    const entity = trustedEntity()
      .name(p.name, lang)
      .tradeName(p.tradeName ?? p.name, lang)
      .addService(issuance.build())
      .addService(revocation.build())
      .postalAddress(
        {
          Country: p.address?.country ?? state.address.country,
          Locality: p.address?.locality ?? state.address.locality,
          PostalCode: p.address?.postalCode ?? state.address.postalCode,
          StreetAddress: p.address?.street ?? state.address.street,
        },
        lang,
      );
    if (p.informationUri) entity.infoUri(p.informationUri, lang);
    if (p.email) entity.email(p.email, lang);
    return entity.build();
  });

  const nextUpdate = new Date(now.getTime() + (state.validityDays ?? 30) * 86_400_000);

  return createLoTE(
    {
      LoTEVersionIdentifier: 1,
      LoTESequenceNumber: state.sequenceNumber,
      LoTEType: profile.loteType,
      SchemeOperatorName: [{ lang, value: state.schemeOperatorName }],
      SchemeName: [{ lang, value: state.schemeName }],
      SchemeInformationURI: [{ lang, uriValue: state.schemeInformationUri }],
      StatusDeterminationApproach: profile.statusDeterminationApproach,
      SchemeTypeCommunityRules: [{ lang, uriValue: profile.schemeTypeCommunityRules }],
      SchemeTerritory: state.territory,
      ListIssueDateTime: iso(now),
      NextUpdate: iso(nextUpdate),
    },
    entities,
  );
}

/**
 * Firma el LoTE y devuelve el **JWS compacto**, que es lo que se publica.
 *
 * `signLoTE` devuelve un objeto envoltorio `{ jws, ... }`; escribir ese objeto
 * en el fichero rompería a cualquier consumidor, porque todos —EUDIPLO
 * incluido— hacen `decodeJwt` sobre el cuerpo de la respuesta tal cual.
 */
export async function signLoteCompact(lote, signer, keyId) {
  const signed = await signLote(lote, signer, keyId);
  return typeof signed === 'string' ? signed : signed.jws;
}

/**
 * Verificación de vuelta, igual que la hace un consumidor: firma del JWS contra
 * el certificado del firmante, y `NextUpdate` no vencido. Es el mismo par de
 * comprobaciones que hace `TrustListJwtService` en EUDIPLO.
 */
export async function verifyLoteCompact(compactJws, signerCertPem) {
  const key = await importX509(signerCertPem, 'ES256');
  await jwtVerify(compactJws, key, { clockTolerance: 300 });
  const payload = decodeJwt(compactJws);
  const info = payload.LoTE?.ListAndSchemeInformation ?? payload.LoTE ?? {};
  const nextUpdate = info.NextUpdate;
  const stale = nextUpdate ? new Date(nextUpdate) < new Date() : true;
  return { payload, nextUpdate, stale, entities: payload.LoTE?.TrustedEntitiesList?.length ?? 0 };
}

/** Firma el LoTE como JWS con nuestro `Signer` (contrato 2). */
export function signLote(lote, signer, keyId) {
  return signLoTE({
    lote,
    keyId,
    algorithm: 'ES256',
    certificates: signer.certificateChain,
    // `signLoTE` concatena lo que devuelva el signer directamente detrás del
    // signing input, así que espera la firma YA en base64url —no bytes—. La
    // conversión vive aquí, en el adaptador, y no en la interfaz `Signer`,
    // que sigue hablando en bytes para todos los demás.
    signer: async (data) => toBase64Url(await signer.sign(data)),
  });
}

/**
 * Comprobaciones sobre el documento ya construido: validez estructural según
 * la librería, y coherencia entre el tipo de lista y los tipos de servicio.
 * Esa coherencia es justo lo que EUDIPLO no puede expresar hoy —cablea
 * `EAA/Issuance` para cualquier lista—, y es la razón de que un tenant
 * instrumental no pudiera publicar una lista de Access CAs.
 */
export function assertLote(lote, state) {
  const problems = [];
  const profile = LIST_PROFILES[state.loteType];

  const structural = validateLoTE(lote);
  if (!structural.valid) {
    for (const e of structural.errors ?? []) problems.push(`estructura: ${e.message ?? e}`);
  }

  const expected = [`${profile.svc}/Issuance`, `${profile.svc}/Revocation`];
  for (const [i, entity] of (lote.LoTE?.TrustedEntitiesList ?? []).entries()) {
    for (const svc of entity.TrustedEntityServices ?? []) {
      const type = svc.ServiceInformation?.ServiceTypeIdentifier;
      if (!expected.includes(type)) {
        problems.push(`entidad[${i}]: tipo de servicio ${type} no corresponde a ${state.loteType}`);
      }
    }
  }
  return problems;
}


/**
 * Cláusula 6.6.3: el `organizationName` del certificado publicado debería
 * coincidir exactamente con el nombre de la entidad (`TEName`).
 *
 * Es **should** en la cláusula general —así que en los anexos D a G es un
 * aviso— y **shall** en el anexo H, que lo repite con esas palabras. La
 * diferencia se conserva porque es la que hay: convertir el should en error
 * bloquearía listas conformes, y rebajar el shall a aviso dejaría pasar una que
 * no lo es.
 *
 * Lo que la norma persigue con esto es que el nombre publicado y el nombre
 * certificado no puedan divergir: sin la comprobación, la lista puede decir
 * "Banco X" sobre un certificado emitido a otro.
 */
export function assertIdentityNaming(state, { subjectOf }) {
  const mandatory = !!LIST_PROFILES[state.loteType]?.namingMandatory;
  const errors = [];
  const warnings = [];

  for (const [i, p] of (state.providers ?? []).entries()) {
    for (const field of ['issuanceCertPem', 'revocationCertPem']) {
      const pem = p[field];
      if (!pem) continue;
      const o = subjectOf(pem);
      const donde = `providers[${i}].${field}`;
      if (o === null) {
        (mandatory ? errors : warnings).push(
          `6.6.3 — ${donde}: el certificado no lleva organizationName en el subject`,
        );
        continue;
      }
      if (o !== p.name) {
        (mandatory ? errors : warnings).push(
          `6.6.3 — ${donde}: organizationName "${o}" no coincide con el nombre de la entidad "${p.name}"`,
        );
      }
    }
  }
  return { errors, warnings };
}
