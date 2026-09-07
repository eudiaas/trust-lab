// Emisión de certificados. Puro: recibe un motor de crypto, devuelve material.
// Sin fs, sin process.env (contrato 1).
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';

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
export async function mintTlSigner(crypto, { schemeOperatorName, territory, commonName, validityDays = 1095 }) {
  const keys = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const now = new Date();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(crypto),
    name: `C=${territory}, O=${schemeOperatorName}, CN=${commonName ?? schemeOperatorName}`,
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

/** La cláusula 5.7.1 convertida en test. Devuelve los incumplimientos. */
export function assertTlsoProfile(certPem, { schemeOperatorName, territory }) {
  const cert = new x509.X509Certificate(certPem);
  const problems = [];
  const dn = new x509.Name(cert.subject);
  const c = dn.getField('C')[0];
  const o = dn.getField('O')[0];
  if (c !== territory) problems.push(`5.7.1: Subject C=${c} debe ser el Scheme Territory (${territory})`);
  if (o !== schemeOperatorName) problems.push(`5.7.1: Subject O=${o} debe coincidir con Scheme operator name (${schemeOperatorName})`);

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
  return problems;
}
