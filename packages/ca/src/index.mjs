// Emisión de certificados. Puro: recibe un motor de crypto, devuelve material.
// Sin fs, sin process.env (contrato 1).
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { WRPAC_POLICY } from './wrpac.mjs';

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
const DAY = 86_400_000;

/** Serial aleatorio de 8 bytes en hex — nunca Math.random. */
function serial(crypto) {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

/**
 * CA raíz autofirmada. `subject` es un DN completo ("C=ES, O=…, CN=…"), no un
 * CN suelto: el país es parte del perfil en casi todos los perfiles EUDI, y
 * cablearlo (como hace EUDIPLO con `C=DE`) es justo lo que no queremos repetir.
 */
export async function mintCa(crypto, { subject, validityDays = 3650, crlUri, extensions = [] }) {
  const keys = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const now = new Date();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(crypto),
    name: subject,
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + validityDays * DAY),
    signingAlgorithm: ALG,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, false, crypto),
      ...(crlUri ? [new x509.CRLDistributionPointsExtension([crlUri])] : []),
      ...extensions,
    ],
  }, crypto);
  return { keys, cert, pem: cert.toString('pem') };
}

/** Hoja firmada por una CA: access certificate, document signer, firmante de listas. */
export async function mintLeaf(crypto, ca, { subject, validityDays = 365, extensions = [] }) {
  const keys = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const now = new Date();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial(crypto),
    subject,
    issuer: ca.cert.subject,
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + validityDays * DAY),
    signingAlgorithm: ALG,
    publicKey: keys.publicKey,
    signingKey: ca.keys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, false, crypto),
      await x509.AuthorityKeyIdentifierExtension.create(ca.cert, false, crypto),
      ...extensions,
    ],
  }, crypto);
  return { keys, cert, pem: cert.toString('pem'), chainPem: [cert.toString('pem'), ca.pem] };
}

/** id-tsl-kp-tslSigning — { itu-t(0) identified-organization(4) etsi(0) tsl-specification(2231) kp(3) tsl-signing(0) } */
export const OID_TSL_SIGNING = '0.4.0.2231.3.0';

/**
 * Certificado del Trusted List Scheme Operator (TLSO), con el perfil de la
 * **cláusula 5.7.1 de TS 119 612**, que es bastante más estrecho que un cert
 * cualquiera y por eso no vale reutilizar `mintCa`:
 *
 *  · autofirmado (o emitido por un servicio listado en la propia TL);
 *  · Subject: `C` = Scheme Territory y `O` = uno de los Scheme operator name;
 *  · KeyUsage digitalSignature y/o nonRepudiation, **con exclusión de
 *    cualquier otro** — o sea, NO keyCertSign;
 *  · ExtendedKeyUsage debería llevar id-tsl-kp-tslSigning;
 *  · SubjectKeyIdentifier presente;
 *  · BasicConstraints CA=false.
 *
 * El DN se deriva del estado de la lista a propósito: así la regla de
 * coincidencia C/O se cumple por construcción y no por suerte.
 */
export async function mintTlSigner(crypto, { schemeOperatorName, territory, signerCountry, commonName, validityDays = 1095 }) {
  const keys = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const now = new Date();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(crypto),
    name: `C=${signerCountry ?? territory}, O=${schemeOperatorName}, CN=${commonName ?? schemeOperatorName}`,
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + validityDays * DAY),
    signingAlgorithm: ALG,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation,
        true,
      ),
      new x509.ExtendedKeyUsageExtension([OID_TSL_SIGNING], false),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, false, crypto),
    ],
  }, crypto);
  return { keys, cert, pem: cert.toString('pem') };
}

/**
 * La cláusula 5.7.1 convertida en test. Devuelve `{ errors, warnings }`.
 *
 * La regla del país va como **aviso, no error**, y no por comodidad: la propia
 * Comisión no la cumple en la AV TL de producción. Esa lista declara
 * `SchemeTerritory` = "EU" y la firma con un certificado cuyo Subject es
 * `C=LU, O=EUROPEAN COMMISSION` — porque "EU" no es un país ISO 3166 y un
 * certificado cualificado se emite en un Estado miembro concreto. Fallar aquí
 * rechazaría el certificado real, que es peor que avisar.
 */
export function assertTlsoProfile(certPem, { schemeOperatorName, territory, kind } = {}, { checkNaming = true } = {}) {
  const cert = new x509.X509Certificate(certPem);
  const problems = [];
  const warnings = [];
  const dn = new x509.Name(cert.subject);
  const c = dn.getField('C')[0];
  const o = dn.getField('O')[0];
  // La regla de nombres ata el certificado a UN esquema concreto, asi que solo
  // aplica cuando se pregunta por ese esquema. Para saber si un certificado
  // sirve como firmante en general —una lista LoTE, una status list— la
  // pregunta es estructural: CA=false, KeyUsage acotado, EKU y SKI.
  if (checkNaming) {
    // La regla de nombres es comun a los dos formatos, pero NO tiene la misma
    // fuerza. TS 119 602 clausula 6.8.0 dice, sin excepcion: "The 'Country
    // code' and 'Organization' fields in Subject Distinguished Name of the
    // certificate supporting the AdES digital signature SHALL match
    // respectively the 'Scheme Territory' and one of the 'Scheme operator
    // name' values". En TS 119 612 la practica de la propia Comision la
    // contradice —la AV TL de produccion declara territorio EU y la firma con
    // C=LU, porque "EU" no es un pais ISO 3166— asi que alli es aviso.
    const esLote = kind === 'lote-json';
    if (c !== territory) {
      const m = `Subject C=${c} y Scheme Territory=${territory} no coinciden`;
      if (esLote) problems.push(`TS 119 602 6.8.0: ${m} (aqui es "shall", sin excepcion)`);
      else warnings.push(`5.7.1: ${m} (la AV TL de producción hace lo mismo: C=LU con territorio EU)`);
    }
    if (o !== schemeOperatorName) {
      problems.push(
        `${esLote ? 'TS 119 602 6.8.0' : '5.7.1'}: Subject O=${o} debe coincidir con ` +
          `Scheme operator name (${schemeOperatorName})`,
      );
    }
  }

  const bc = cert.getExtension('2.5.29.19');
  if (bc?.ca) problems.push('5.7.1: BasicConstraints debe indicar CA=false');

  const ku = cert.getExtension('2.5.29.15');
  if (!ku) problems.push('5.7.1: falta KeyUsage');
  else {
    const allowed = x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation;
    if (ku.usages & ~allowed) problems.push(`5.7.1: KeyUsage lleva bits fuera de digitalSignature/nonRepudiation`);
  }

  const eku = cert.getExtension('2.5.29.37');
  if (!eku?.usages?.includes(OID_TSL_SIGNING))
    problems.push('5.7.1: ExtendedKeyUsage debería contener id-tsl-kp-tslSigning (0.4.0.2231.3.0)');

  if (!cert.getExtension('2.5.29.14')) problems.push('5.7.1: falta SubjectKeyIdentifier');
  return { errors: problems, warnings };
}

/**
 * Que es una entrada del almacen de claves, leido del propio certificado.
 *
 * El almacen guarda pares clave+certificado bajo un nombre, y el nombre lo
 * pone quien la emite: mirando la lista no se distingue una CA de un firmante
 * de listas de un access certificate. Aqui la respuesta sale de las
 * extensiones, que es donde esta de verdad.
 */
export function describeKey(certPem) {
  let cert;
  try {
    cert = new x509.X509Certificate(certPem);
  } catch {
    return { role: 'ilegible' };
  }
  const bc = cert.getExtension('2.5.29.19');
  const eku = cert.getExtension('2.5.29.37')?.usages ?? [];
  const policies = cert.getExtension('2.5.29.32');
  // El OID de politica es lo unico que distingue un access certificate de una
  // hoja cualquiera: TS 119 411-8 le asigna cuatro, y `mintWrpac` pone uno.
  const wrpacOid = Object.entries(WRPAC_POLICY).find(([, oid]) =>
    (policies?.policies ?? []).some((p) => (p.policyIdentifier ?? p) === oid),
  );

  const role = bc?.ca
    ? 'CA'
    : eku.includes(OID_TSL_SIGNING)
      ? 'firmante de listas'
      : wrpacOid
        ? 'access certificate'
        : 'hoja';

  return {
    role,
    ca: !!bc?.ca,
    policy: wrpacOid?.[0],
    selfSigned: cert.subject === cert.issuer,
    issuer: cert.issuer,
    notAfter: cert.notAfter?.toISOString().slice(0, 10),
    expired: cert.notAfter ? cert.notAfter < new Date() : null,
  };
}

// ---------------------------------------------------------------------------
// Firmantes de credenciales y atestaciones
//
// Hasta ahora solo habia dos perfiles de hoja con nombre: el firmante de listas
// (5.7.1) y el access certificate (TS 119 411-8). Todo lo demas —el Document
// Signer del PID, el que firma los registration certificates, el de la Wallet
// Instance Attestation y el de la Key Attestation— habia que sacarlo con
// `mint-leaf` a mano, y en la practica se acababa firmando con el TLSO, que
// NO encadena con la CA declarada en la lista que corresponde. Una cadena que
// no llega a la lista no es una cadena.
//
// Lo que estas entradas fijan es la ESTRUCTURA y el parentesco, que es lo que
// hace que la cadena cierre. Donde hay un EKU normativo, va; donde no lo tengo
// contrastado contra la norma, no se inventa: la confianza en estos artefactos
// la establece el encadenamiento con el ancla publicada en la lista, no un OID
// de adorno.
// ---------------------------------------------------------------------------

/** EKU de Document Signer de mdoc (ISO/IEC 18013-5 Anexo B). */
export const OID_MDOC_DS = '1.0.18013.5.1.2';

/**
 * Perfiles de certificado. Son DOS, no cinco.
 *
 * Los papeles que un operador nombra ("el DS del PID", "el que firma la Key
 * Attestation") son mas que los perfiles que existen de verdad, porque varios
 * papeles distintos se firman con un certificado del mismo tipo. Definir un
 * perfil por papel era duplicacion: dos entradas identicas salvo la etiqueta
 * divergen en cuanto alguien toca una y no la otra.
 *
 * Asi que los perfiles se definen una vez y los papeles apuntan a ellos. Que
 * dos papeles compartan perfil queda dicho, en vez de descubrirse comparando.
 */
const PROFILE = {
  'mdoc-ds': {
    eku: [OID_MDOC_DS],
    validityDays: 365,
    // ISO/IEC 18013-5 monta el Document Signer bajo una IACA. TS 119 602 no lo
    // exige —su criterio es funcional— pero un verificador de mdoc que valide
    // la jerarquia rechazaria un DS autofirmado, y esa variable no compensa
    // dejarla abierta cuando la CA cuesta un comando.
    requiresCa: 'un Document Signer de mdoc cuelga de una IACA (ISO/IEC 18013-5)',
  },
  jws: { eku: null, validityDays: 1095, requiresCa: null },
};

export const SIGNER_ROLES = {
  'mdoc-ds': {
    profile: 'mdoc-ds',
    label: 'Document Signer de mdoc',
    lista: 'la lista del emisor (AV TL para AV, LoTE de PID para PID)',
    nota: 'Firma los MSO. La AV Trusted List publica el DS, no la IACA.',
  },
  'pid-ds': {
    profile: 'mdoc-ds',
    label: 'Document Signer del PID en mso_mdoc',
    lista: 'EUPIDProvidersList (pid-lab)',
    nota:
      'Es el MISMO perfil que mdoc-ds, porque un PID en mso_mdoc es un mdoc: ' +
      'cambia de quien cuelga y en que lista se publica, no el certificado. ' +
      'Un PID en dc+sd-jwt no lleva este EKU y seria otro perfil (no implementado).',
  },
  wrprc: {
    profile: 'jws',
    label: 'firmante de registration certificates',
    lista: 'EUWRPRCProvidersList (wrprc-lab)',
    nota:
      'TS 119 475 no le exige el EKU id-tsl-kp-tslSigning: eso es de TS 119 612 ' +
      'y solo aplica a quien firma listas. Su cadena va en el x5c del propio JWS.',
  },
  wia: {
    profile: 'jws',
    label: 'firmante de Wallet Instance Attestation',
    lista: 'EUWalletProvidersList (wallet-lab)',
    nota: 'Cuelga del wallet provider, que es el ancla publicada en la lista.',
  },
  'key-attestation': {
    profile: 'jws',
    label: 'firmante de Key Attestation',
    lista: 'EUWalletProvidersList (wallet-lab)',
    nota:
      'Mismo perfil que wia. Ninguna norma consultada obliga a separarlos, y el ' +
      'anexo E de TS 119 602 admite "one or more X.509 certificates" en la misma ' +
      'entrada, asi que uno solo vale. Se mantienen como papeles distintos porque ' +
      'atestiguan cosas distintas y se pueden querer rotar aparte — no porque el ' +
      'certificado tenga que ser otro.',
  },
};

/** El papel resuelto contra su perfil. */
export function signerRole(role) {
  const r = SIGNER_ROLES[role];
  if (!r) return null;
  return { ...PROFILE[r.profile], ...r };
}

/**
 * Hoja con uno de los papeles de arriba, firmada por la CA que toca.
 *
 * La diferencia con `mintLeaf` no es criptografica, es de intencion declarada:
 * el rol queda escrito en el certificado (via EKU cuando lo hay) y, sobre todo,
 * queda escrito de QUIEN cuelga — que es lo que decide si la cadena llega o no
 * al ancla que publica la lista.
 */
export async function mintRoleSigner(crypto, ca, { role, subject, validityDays }) {
  const spec = signerRole(role);
  if (!spec) {
    throw new Error(`rol desconocido: ${role} (usa uno de: ${Object.keys(SIGNER_ROLES).join(', ')})`);
  }
  if (!ca && spec.requiresCa) throw new Error(`${spec.requiresCa}: falta el emisor`);
  const extensions = spec.eku ? [new x509.ExtendedKeyUsageExtension(spec.eku, false)] : [];
  const days = validityDays ?? spec.validityDays;

  // Sin CA, autofirmado. No es un atajo: en las listas que publican el
  // certificado FIRMANTE (TS 119 602 anexos D, E, G, y la AV TL), lo que se
  // publica es este certificado, asi que no hay ninguna cadena que recorrer y
  // una jerarquia por encima no aporta nada al veredicto.
  //
  // Lo que NO sirve para esto es `mintCa`: da CA:TRUE con KeyUsage
  // keyCertSign/cRLSign y sin digitalSignature, asi que un verificador que
  // mire el KeyUsage rechaza la firma. De ahi que esto exista y no baste con
  // "usa una CA autofirmada".
  if (!ca) {
    const leaf = await mintSelfSignedLeaf(crypto, { subject, validityDays: days, extensions });
    return { ...leaf, role, spec, selfSigned: true };
  }

  const leaf = await mintLeaf(crypto, ca, { subject, validityDays: days, extensions });
  return { ...leaf, role, spec, selfSigned: false };
}

/** Hoja autofirmada: perfil de firma (CA=false, digitalSignature), sin emisor. */
export async function mintSelfSignedLeaf(crypto, { subject, validityDays = 365, extensions = [] }) {
  const keys = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const now = new Date();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(crypto),
    name: subject,
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + validityDays * DAY),
    signingAlgorithm: ALG,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, false, crypto),
      ...extensions,
    ],
  }, crypto);
  return { keys, cert, pem: cert.toString('pem'), chainPem: [cert.toString('pem')] };
}
