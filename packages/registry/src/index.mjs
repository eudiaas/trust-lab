// El registro de una Wallet-Relying Party, con el modelo de datos de **TS5**
// ("Common formats and API for Relying Party Registration information") y el
// conjunto mínimo de atributos de **TS6**, que a su vez baja del CIR (EU)
// 2025/848 Annex I ampliado por el CIR (EU) 2026/1730.
//
// Por qué el modelo de las especificaciones y no uno propio: es el registro lo
// que un Registrar nacional guardaría, y de él se derivan *los dos*
// certificados — el de acceso (GEN-6.6.1-10 de TS 119 411-8 lo dice
// literalmente) y el de registro. Un modelo propio obligaría a traducir dos
// veces y a mantener la traducción.
//
// La jerarquía de TS5, que es donde más se nota la diferencia con un modelo
// improvisado:
//
//   WalletRelyingParty            ← la entidad legal registrada
//     └── services[]              ← WalletRelyingPartyService (¡este nivel!)
//           └── intendedUses[]    ← un WRPRC por cada uno
//                 └── credentials[] → claims[]
//
// El nivel «servicio» no está en el reglamento: TS5 lo añade a propósito para
// que un RP pueda separar instancias, certificados de acceso y finalidades.

/** Tipos de identificador de TS 119 475 tabla 2 / TS6 §3, con su prefijo semántico EN 319 412-1. */
export const IDENTIFIER_TYPES = {
  'http://data.europa.eu/eudi/id/EORI-No': 'EOR',
  'http://data.europa.eu/eudi/id/LEI': 'LEI',
  'http://data.europa.eu/eudi/id/EUID': 'NTR',
  'http://data.europa.eu/eudi/id/VATIN': 'VAT',
  'http://data.europa.eu/eudi/id/TIN': { legalPerson: 'VAT', naturalPerson: 'TIN' },
  'http://data.europa.eu/eudi/id/Excise': 'EXC',
};

export const ENTITLEMENT_BASE = 'https://uri.etsi.org/19475/Entitlement/';
export const ENTITLEMENTS = [
  'Service_Provider', 'QEAA_Provider', 'Non_Q_EAA_Provider', 'PUB_EAA_Provider',
  'PID_Provider', 'QCert_for_ESeal_Provider', 'QCert_for_ESig_Provider',
  'rQSealCDs_Provider', 'rQSigCDs_Provider', 'ESig_ESeal_Creation_Provider',
].map((e) => ENTITLEMENT_BASE + e);

/**
 * Identificador semántico de EN 319 412-1 §5.1.3/5.1.4:
 * `<3 letras><país>-<valor>`. Es el mismo string que va al
 * `organizationIdentifier` del access certificate y al `sub` del WRPRC, así
 * que se **deriva** del identificador tipado del registro en vez de escribirse
 * a mano en dos sitios.
 */
export function semanticIdentifier(identifier, subjectType = 'legalPerson') {
  const prefix = IDENTIFIER_TYPES[identifier.type];
  if (!prefix) throw new Error(`tipo de identificador desconocido: ${identifier.type}`);
  const p = typeof prefix === 'string' ? prefix : prefix[subjectType];
  // "EL" para Grecia, no "GR" (TS6 §6 y GEN-6.6.1-05 de TS 119 411-8).
  const cc = identifier.country === 'GR' ? 'EL' : identifier.country;
  return `${p}${cc}-${identifier.value}`;
}

/** El identificador primario: el marcado, o el primero declarado. */
export function primaryIdentifier(wrp) {
  const ids = wrp.identifier ?? [];
  if (!ids.length) throw new Error('TS6 §3: el registro no declara ningún identifier');
  return ids.find((i) => i.primary) ?? ids[0];
}

export function findService(wrp, serviceId) {
  const svc = (wrp.services ?? []).find(
    (s) => s.serviceIdentifier === serviceId || s.serviceTradeName === serviceId,
  );
  if (!svc) throw new Error(`servicio desconocido: ${serviceId}`);
  return svc;
}

export function findIntendedUse(service, useId) {
  const use = (service.intendedUses ?? []).find((u) => u.intendedUseIdentifier === useId);
  if (!use) throw new Error(`intended use desconocido: ${useId}`);
  return use;
}

/**
 * Las multiplicidades de TS5 §2.1 y §2.4.1 convertidas en test, más los
 * mínimos de TS6. No cubre el JSON Schema normativo del anexo A de TS5 —
 * cuando haga falta esa profundidad, se valida contra él directamente.
 */
export function assertRegistry(reg) {
  const wrp = reg.walletRelyingParty;
  const problems = [];
  const req = (cond, msg) => { if (!cond) problems.push(msg); };

  req(!!wrp, 'falta walletRelyingParty');
  if (!wrp) return problems;

  req(!!wrp.legalName || (wrp.givenName && wrp.familyName),
    'TS6 §1: hace falta legalName (persona jurídica) o givenName+familyName (física)');
  req(Array.isArray(wrp.identifier) && wrp.identifier.length > 0, 'TS6 §3: identifier [1..*]');
  for (const [i, id] of (wrp.identifier ?? []).entries()) {
    req(!!IDENTIFIER_TYPES[id.type], `identifier[${i}].type no es uno de los de TS 119 475 tabla 2`);
    req(/^[A-Z]{2}$/.test(id.country ?? ''), `identifier[${i}].country debe ser ISO 3166-1 alpha-2`);
    req(!!id.value, `identifier[${i}].value es obligatorio`);
  }
  req(typeof wrp.isPSB === 'boolean', 'TS5 §2.1: isPSB [1..1] y booleano');
  req(!!wrp.registryURI, 'TS5 §2.1: registryURI [1..1]');

  const sa = wrp.supervisoryAuthority;
  req(!!sa, 'TS5 §2.1: supervisoryAuthority [1..1]');
  if (sa) {
    // ARF RPRC_12, citado por TS5 §2.4.7: nombre y país son obligatorios.
    req(!!sa.name, 'TS5 §2.4.7: supervisoryAuthority.name [1..1]');
    req(/^[A-Z]{2}$/.test(sa.country ?? ''), 'TS5 §2.4.7: supervisoryAuthority.country [1..1]');
    req(!!(sa.email?.length || sa.phone?.length || sa.formURI?.length),
      'TS5 §2.4.7: al menos uno de email, phone o formURI');
  }

  req(Array.isArray(wrp.services) && wrp.services.length > 0, 'TS5 §2.1: services [1..*]');
  for (const [i, s] of (wrp.services ?? []).entries()) {
    req(!!s.serviceTradeName, `services[${i}]: serviceTradeName [1..1]`);
    req(!!(s.supportURI || s.email || s.phone),
      `services[${i}]: TS6 §7 exige al menos uno de supportURI, email o phone`);
    req(Array.isArray(s.srvDescription) && s.srvDescription.length > 0,
      `services[${i}]: srvDescription [1..*]`);
    req(typeof s.isIntermediary === 'boolean', `services[${i}]: isIntermediary [1..1]`);
    if (s.usesIntermediaries?.length && s.isIntermediary !== false) {
      problems.push(`services[${i}]: isIntermediary debe ser false si hay usesIntermediaries`);
    }
    if (s.usesIntermediaries?.length && !s.serviceIdentifier) {
      problems.push(`services[${i}]: TS5 §2.4.1 — un RP que usa intermediario SHALL registrar serviceIdentifier`);
    }
    for (const e of s.entitlements ?? []) {
      if (!ENTITLEMENTS.includes(e)) problems.push(`services[${i}]: entitlement no reconocido ${e}`);
    }
    const providerEnts = ['QEAA_Provider', 'Non_Q_EAA_Provider', 'PUB_EAA_Provider', 'PID_Provider']
      .map((e) => ENTITLEMENT_BASE + e);
    const isProvider = (s.entitlements ?? []).some((e) => providerEnts.includes(e));
    if (isProvider && !(s.providesAttestations ?? []).length) {
      problems.push(`services[${i}]: TS6 — providesAttestations es obligatorio con entitlements de proveedor`);
    }
    for (const [j, u] of (s.intendedUses ?? []).entries()) {
      req(!!u.intendedUseIdentifier, `services[${i}].intendedUses[${j}]: intendedUseIdentifier [1..1]`);
      req(!!u.createdAt, `services[${i}].intendedUses[${j}]: createdAt [1..1]`);
      req((u.purpose ?? []).length > 0, `services[${i}].intendedUses[${j}]: purpose [1..*]`);
      req((u.privacyPolicy ?? []).length > 0, `services[${i}].intendedUses[${j}]: privacyPolicy [1..*]`);
      req((u.credentials ?? []).length > 0, `services[${i}].intendedUses[${j}]: credentials [1..*]`);
      for (const [k, c] of (u.credentials ?? []).entries()) {
        req(!!c.format, `…credentials[${k}]: format [1..1]`);
        req(!!c.meta, `…credentials[${k}]: meta [1..1]`);
        req((c.claims ?? []).length > 0, `…credentials[${k}]: claims [1..*]`);
      }
    }
  }
  return problems;
}

/** Registro → lo que necesita `mintWrpac` (TS 119 411-8, cláusula 6.6.1). */
export function toWrpacSpec(reg, serviceId) {
  const wrp = reg.walletRelyingParty;
  const svc = findService(wrp, serviceId);
  return {
    country: primaryIdentifier(wrp).country,
    organization: wrp.legalName,
    // GEN-6.1.1-04: el CN puede ser el nombre comercial o de servicio
    // reconocible por el usuario — que es exactamente serviceTradeName.
    commonName: svc.serviceTradeName,
    organizationalUnit: svc.serviceIdentifier,
    organizationIdentifier: semanticIdentifier(primaryIdentifier(wrp)),
    policy: reg.wrpac?.policy ?? 'NCP-l-eudiwrp',
    cpsUri: reg.wrpac?.cpsUri,
    contact: { uri: svc.supportURI, email: svc.email, phone: svc.phone },
    validityDays: reg.wrpac?.validityDays ?? 365,
  };
}

/**
 * Registro → entrada del builder de WRPRC.
 *
 * Aquí se ve el desajuste de vocabulario entre las dos familias de
 * especificación: TS5 dice `MultiLangString{lang, content}` y ETSI TS 119 475
 * dice `{lang, value}`; TS5 dice `srvDescription`, `privacyPolicy`,
 * `supervisoryAuthority.name/country`, y el certificado v1.2.1 dice
 * `srv_description`, `privacy_policy` y una autoridad de control **sin**
 * nombre ni país. La traducción vive aquí y en un solo sitio.
 */
export function toWrprcInput(reg, serviceId, intendedUseId) {
  const wrp = reg.walletRelyingParty;
  const svc = findService(wrp, serviceId);
  const use = findIntendedUse(svc, intendedUseId);
  const ml = (arr) => (arr ?? []).map((x) => ({ lang: x.lang, value: x.content ?? x.value }));

  return {
    tradeName: svc.serviceTradeName ?? wrp.tradeName ?? wrp.legalName,
    legalName: wrp.legalName,
    identifier: semanticIdentifier(primaryIdentifier(wrp)),
    country: primaryIdentifier(wrp).country,
    registryUri: wrp.registryURI,
    isPSB: wrp.isPSB,
    entitlements: svc.entitlements ?? [],
    subEntitlements: svc.subEntitlements ?? [],
    srvDescription: ml(svc.srvDescription),
    supportUri: svc.supportURI,
    infoUri: wrp.infoURI,
    purpose: ml(use.purpose),
    privacyPolicy: use.privacyPolicy?.[0]?.uri ?? use.privacyPolicy?.[0],
    intendedUseIdentifier: use.intendedUseIdentifier,
    credentials: use.credentials,
    supervisoryAuthority: wrp.supervisoryAuthority,
  };
}

/**
 * Registro nuevo: un esqueleto **que ya valida**.
 *
 * La alternativa —un documento incompleto que el editor rechaza al guardar—
 * obligaria a rellenar cuarenta campos anidados de una sentada antes de poder
 * salvar nada. Asi el operador crea la entidad, y a partir de ahi cambia
 * valores de uno en uno con la validacion actuando de red. El precio es que
 * los valores de relleno son visiblemente de relleno: si alguien emite un
 * certificado sin tocarlos, se ve en el subject.
 *
 * El servicio y la finalidad de ejemplo son los del caso que este laboratorio
 * existe para probar (AV, `age_over_18` sobre `eu.europa.ec.av.1`).
 */
export function newRegistry({
  legalName,
  country = 'ES',
  identifierType = 'http://data.europa.eu/eudi/id/VATIN',
  identifierValue,
  baseUrl = 'https://trust-lab.example',
  supervisoryAuthority,
  serviceId = 'svc-1',
  intendedUseId = 'use-1',
  cpsUri,
  statusList,
  today = new Date().toISOString().slice(0, 10),
} = {}) {
  if (!legalName) throw new Error('hace falta legalName');
  if (!identifierValue) throw new Error('hace falta el valor del identificador');
  if (!IDENTIFIER_TYPES[identifierType]) throw new Error(`tipo de identificador desconocido: ${identifierType}`);
  if (!/^[A-Z]{2}$/.test(country)) throw new Error('country debe ser ISO 3166-1 alpha-2');

  const base = baseUrl.replace(/\/+$/, '');
  const semantic = semanticIdentifier({ type: identifierType, value: identifierValue, country });

  return {
    _model:
      'TS5 (Common formats and API for RP Registration information) + TS6 (Common set of RP information to be registered).',
    walletRelyingParty: {
      legalName,
      identifier: [{ type: identifierType, value: identifierValue, country, primary: true }],
      infoURI: `${base}/rp/${encodeURIComponent(semantic)}`,
      isPSB: false,
      registryURI: `${base}/registry/${country.toLowerCase()}/${semantic}`,
      supervisoryAuthority: supervisoryAuthority ?? {
        name: 'PENDIENTE — autoridad de control competente',
        country,
        formURI: [`${base}/pendiente`],
      },
      services: [
        {
          serviceTradeName: legalName,
          serviceIdentifier: serviceId,
          supportURI: `${base}/pendiente`,
          srvDescription: [{ lang: 'en', content: 'PENDIENTE — description of the service' }],
          entitlements: [ENTITLEMENT_BASE + 'Service_Provider'],
          isIntermediary: false,
          intendedUses: [
            {
              intendedUseIdentifier: intendedUseId,
              createdAt: today,
              purpose: [{ lang: 'en', content: 'PENDIENTE — purpose of the data request' }],
              privacyPolicy: [{ uri: `${base}/pendiente`, type: 'PrivacyStatement' }],
              credentials: [
                {
                  format: 'mso_mdoc',
                  meta: { doctype_value: 'eu.europa.ec.av.1' },
                  claims: [{ path: ['eu.europa.ec.av.1', 'age_over_18'] }],
                },
              ],
            },
          ],
        },
      ],
    },
    wrpac: { policy: 'NCP-l-eudiwrp', cpsUri: cpsUri ?? `${base}/cps`, validityDays: 365 },
    ...(statusList ? { statusList } : {}),
  };
}
