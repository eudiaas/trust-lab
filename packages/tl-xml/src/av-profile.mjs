// Perfil de la **AV Trusted List** — "AV Trusted List Specifications" v1.1.0
// (Comisión Europea, DIGIT.B.3, 20.10.2025), tablas I.1, I.2 y I.3.
//
// Su §3 dice: «The AV trusted list shall be a trusted list compliant to ETSI
// TS 119 612 v2.4.1», y encima fija por valor doce campos. Como el objetivo es
// que una wallet trate nuestra lista de laboratorio EXACTAMENTE igual que la
// real —cambiando sólo quién la firma y quién está dentro—, estos valores no
// son un default sugerido: divergir de ellos es un error, salvo que se pida
// explícitamente.
//
// (El documento se contradice a sí mismo: §2 y la tabla de referencias citan
// v2.3.1 mientras §3 exige v2.4.1. Da igual para nosotros: comparadas las dos,
// las reglas de presencia de la cláusula 5, el Annex B y la cláusula 5.7.1 son
// idénticas palabra por palabra.)

export const AV_TL_PROFILE = {
  name: 'eu-age-verification',
  tslType: 'http://trust.tech.ec.europa.eu/lists/age-verification/tsl-type',
  serviceType: 'http://trust.tech.ec.europa.eu/lists/age-verification/service-type/paa',
  serviceStatuses: [
    'http://trust.tech.ec.europa.eu/lists/age-verification/service-status/recognized',
    'http://trust.tech.ec.europa.eu/lists/age-verification/service-status/deprecated',
  ],
  // Tabla I.1 — valores fijados por la Comisión.
  schemeName:
    'EU:List containing the information notified by EU Member States on authorised Proof of Age Attestation Providers.',
  schemeInformationUri: 'http://trust.tech.ec.europa.eu/lists/age-verification/scheme-information',
  statusDeterminationApproach:
    'http://trust.tech.ec.europa.eu/lists/age-verification/status-determination/compliance-declaration',
  schemeTypeCommunityRules: 'http://trust.tech.ec.europa.eu/lists/age-verification/scheme-rules',
  territory: 'EU',
  legalNotice:
    'The present list contains information notified by Member States on the Proof of Age Attestation Providers and the Proof of Age Services they provide for the purpose of facilitating compliance of online services with Article 28 of the Digital Services Act. The European Commission maintains this website as an interoperability tool designed to facilitate the practical use of the age-verification trusted list. The European Commission seeks to keep the information accurate and timely correct errors that are brought to its attention. Without prejudice to provisions laid down in applicable national or Union law, the European Commission, however, does not accept liability or responsibility for any problems incurred as a result of using the age-verification trusted list or any information contained therein. The responsibility and liability with regard to the provision of listed services lie exclusively with the Proof of Age Attestation Providers providing them.',
  // Tabla I.2 — el TSP information URI de cada PAAP lleva el código del EM.
  paapInformationUriPrefix: 'http://trust.tech.ec.europa.eu/lists/age-verification/paap/',
  // Cláusula 6.2 de TS 119 612, para el puntero a sí misma.
  mimeType: 'application/vnd.etsi.tsl+xml',
  // Tabla I.1: "Scheme extensions — This field shall not be used"; tabla I.3:
  // "Qualification extensions shall not be used". No emitimos ninguna de las dos.
};

/**
 * El perfil AV convertido en test. Devuelve los incumplimientos del estado.
 *
 * `allowDivergence: true` en el estado los degrada a avisos: sirve para una
 * lista de laboratorio que quiera ser distinguible a simple vista, a cambio de
 * que una wallet estricta pueda rechazarla por un motivo que no es el que
 * queríamos probar.
 */
export function assertAvProfile(state) {
  const problems = [];
  const eq = (field, actual, expected) => {
    if (actual !== expected) {
      problems.push(`AV TL tabla I.1 — ${field}:\n      es       ${JSON.stringify(actual)}\n      debe ser ${JSON.stringify(expected)}`);
    }
  };

  eq('Scheme name (5.3.6)', state.schemeName, AV_TL_PROFILE.schemeName);
  eq('Scheme information URI (5.3.7)', state.schemeInformationUri?.[0], AV_TL_PROFILE.schemeInformationUri);
  eq('Status determination approach (5.3.8)', state.statusDeterminationApproach, AV_TL_PROFILE.statusDeterminationApproach);
  eq('Scheme type/community/rules (5.3.9)', state.schemeTypeCommunityRules?.[0], AV_TL_PROFILE.schemeTypeCommunityRules);
  eq('Scheme territory (5.3.10)', state.territory, AV_TL_PROFILE.territory);
  eq('TSL policy/legal notice (5.3.11)', state.legalNotice?.[0], AV_TL_PROFILE.legalNotice);

  // Tabla I.1: "Pointers to other TSLs — Value: Pointer to itself."
  if (!state.pointerToSelf) {
    problems.push('AV TL tabla I.1 — Pointers to other TSLs (5.3.13): falta el puntero a sí misma');
  }

  for (const [i, p] of (state.providers ?? []).entries()) {
    // Tabla I.2: el TSP information URI lleva el código ISO del EM donde el
    // PAAP está establecido.
    const uri = p.informationUri?.[0];
    if (!uri?.startsWith(AV_TL_PROFILE.paapInformationUriPrefix)) {
      problems.push(`AV TL tabla I.2 — providers[${i}].informationUri debe empezar por ${AV_TL_PROFILE.paapInformationUriPrefix}<CC>`);
    }
    // Tabla I.3: sólo recognized o deprecated, "to the exclusion of any other".
    if (p.status && !AV_TL_PROFILE.serviceStatuses.includes(p.status)) {
      problems.push(`AV TL tabla I.3 — providers[${i}].status "${p.status}" no es recognized ni deprecated`);
    }
  }

  return problems;
}
