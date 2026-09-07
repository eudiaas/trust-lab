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
export function assertTlsoProfile(certPem, { schemeOperatorName, territory } = {}, { checkNaming = true } = {}) {
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
    if (c !== territory) warnings.push(`5.7.1: Subject C=${c} y Scheme Territory=${territory} no coinciden (la AV TL de producción hace lo mismo: C=LU con territorio EU)`);
    if (o !== schemeOperatorName) problems.push(`5.7.1: Subject O=${o} debe coincidir con Scheme operator name (${schemeOperatorName})`);
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

export const SIGNER_ROLES = {
  'mdoc-ds': {
    label: 'Document Signer de mdoc',
    eku: [OID_MDOC_DS],
    validityDays: 365,
    lista: 'la lista del emisor (AV TL para AV, LoTE de PID para PID)',
    nota: 'Firma los MSO. La AV Trusted List lleva el DS, no la IACA.',
  },
  'pid-ds': {
    label: 'Document Signer del PID',
    eku: [OID_MDOC_DS],
    validityDays: 365,
    lista: 'EUPIDProvidersList (pid-lab)',
    nota: 'Mismo perfil que cualquier DS de mdoc; cambia de quien cuelga.',
  },
  wrprc: {
    label: 'firmante de registration certificates',
    eku: null,
    validityDays: 1095,
    lista: 'EUWRPRCProvidersList (wrprc-lab)',
    nota:
      'TS 119 475 no le exige el EKU id-tsl-kp-tslSigning: eso es de TS 119 612 ' +
      'y solo aplica a quien firma listas. Su cadena va en el x5c del propio JWS.',
  },
  wia: {
    label: 'firmante de Wallet Instance Attestation',
    eku: null,
    validityDays: 1095,
    lista: 'EUWalletProvidersList (wallet-lab)',
    nota: 'Cuelga del wallet provider, que es el ancla publicada en la lista.',
  },
  'key-attestation': {
    label: 'firmante de Key Attestation',
    eku: null,
    validityDays: 1095,
    lista: 'EUWalletProvidersList (wallet-lab)',
    nota: 'Puede ser el mismo que el de WIA; se separa por si se quiere rotar aparte.',
  },
};

/**
 * Hoja con uno de los papeles de arriba, firmada por la CA que toca.
 *
 * La diferencia con `mintLeaf` no es criptografica, es de intencion declarada:
 * el rol queda escrito en el certificado (via EKU cuando lo hay) y, sobre todo,
 * queda escrito de QUIEN cuelga — que es lo que decide si la cadena llega o no
 * al ancla que publica la lista.
 */
export async function mintRoleSigner(crypto, ca, { role, subject, validityDays }) {
  const spec = SIGNER_ROLES[role];
  if (!spec) {
    throw new Error(`rol desconocido: ${role} (usa uno de: ${Object.keys(SIGNER_ROLES).join(', ')})`);
  }
  const leaf = await mintLeaf(crypto, ca, {
    subject,
    validityDays: validityDays ?? spec.validityDays,
    extensions: spec.eku ? [new x509.ExtendedKeyUsageExtension(spec.eku, false)] : [],
  });
  return { ...leaf, role, spec };
}
