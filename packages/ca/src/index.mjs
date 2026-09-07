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
