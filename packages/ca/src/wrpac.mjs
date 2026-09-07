// Wallet-Relying Party Access Certificates (WRPAC) — ETSI TS 119 411-8 v1.1.1
// (2025-10), "Access Certificate Policy for EUDI Wallet Relying Parties",
// escrita para el CIR (EU) 2025/848.
//
// Es el certificado con el que el RP se autentica ante la wallet. En el perfil
// AV con `x509_hash` no se valida cadena (el client_id ES el hash de la hoja),
// pero en `readerAuth` de ISO 18013-7 la wallet SÍ recibe la cadena completa y
// la valida contra su almacén — que es donde este perfil empieza a importar.
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import {
  CertificatePolicies,
  PolicyInformation,
  PolicyQualifierInfo,
  id_qt_csp,
} from '@peculiar/asn1-x509';
import { AsnConvert } from '@peculiar/asn1-schema';

/**
 * Identificadores de política de la cláusula 5.3, bajo el arco
 * `{ itu-t(0) identified-organization(4) etsi(0) eudiwrp(194118)
 *    policy-identifiers(1) }`.
 *
 * La elección no es de estilo: `-n` es para personas físicas (firma
 * electrónica avanzada) y `-l` para jurídicas (sello avanzado); `QCP-*` son
 * las variantes cualificadas. Un RP que es una empresa emite bajo `NCP-l` o
 * `QCP-l`.
 */
export const WRPAC_POLICY = {
  'NCP-n-eudiwrp': '0.4.0.194118.1.1',
  'NCP-l-eudiwrp': '0.4.0.194118.1.2',
  'QCP-n-eudiwrp': '0.4.0.194118.1.3',
  'QCP-l-eudiwrp': '0.4.0.194118.1.4',
};

/** organizationIdentifier (X.520). GEN-6.6.1-05 lo exige para personas jurídicas. */
export const OID_ORGANIZATION_IDENTIFIER = '2.5.4.97';

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
const DAY = 86_400_000;

function serial(crypto) {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

/**
 * Emite un access certificate de RP firmado por una CA.
 *
 * @param opts.policy          clave de WRPAC_POLICY
 * @param opts.organizationIdentifier identificador semántico EN 319 412-1 §5.1.4
 *                             (p. ej. "VATES-B12345678"), obligatorio para
 *                             personas jurídicas por GEN-6.6.1-05
 * @param opts.cpsUri          URL del CPS del proveedor (GEN-6.6.1-06)
 * @param opts.contact         al menos uno: { uri, email, phone } (GEN-6.6.1-07)
 */
export async function mintWrpac(crypto, ca, opts) {
  const {
    country, organization, commonName, organizationalUnit,
    organizationIdentifier, policy = 'NCP-l-eudiwrp', cpsUri, contact = {},
    validityDays = 365,
  } = opts;

  if (!organizationIdentifier) throw new Error('GEN-6.6.1-05: falta organizationIdentifier');
  if (!cpsUri) throw new Error('GEN-6.6.1-06: falta el cpsURI');
  if (!contact.uri && !contact.email && !contact.phone) {
    throw new Error('GEN-6.6.1-07: hace falta al menos un contacto (uri, email o phone)');
  }
  const policyOid = WRPAC_POLICY[policy];
  if (!policyOid) throw new Error(`política desconocida: ${policy}`);

  const keys = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const now = new Date();

  const name = [
    { C: [country] },
    { O: [organization] },
    ...(organizationalUnit ? [{ OU: [organizationalUnit] }] : []),
    { [OID_ORGANIZATION_IDENTIFIER]: [organizationIdentifier] },
    { CN: [commonName] },
  ];

  const san = [];
  if (contact.uri) san.push({ type: 'url', value: contact.uri });
  if (contact.email) san.push({ type: 'email', value: contact.email });

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial(crypto),
    subject: new x509.Name(name).toString(),
    issuer: ca.cert.subject,
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + validityDays * DAY),
    signingAlgorithm: ALG,
    publicKey: keys.publicKey,
    signingKey: ca.keys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.SubjectAlternativeNameExtension(san),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, false, crypto),
      await x509.AuthorityKeyIdentifierExtension.create(ca.cert, false, crypto),
      buildCertificatePolicies(policyOid, cpsUri),
    ],
  }, crypto);

  return { keys, cert, pem: cert.toString('pem'), chainPem: [cert.toString('pem'), ca.pem], policy, policyOid };
}

/**
 * IA5String en DER. La longitud va en forma corta hasta 127 bytes y en forma
 * larga a partir de ahí: una URL de CPS puede pasar de 127 caracteres sin
 * despeinarse, y con la forma corta saldría un certificado corrupto que
 * @peculiar/x509 emite sin protestar y una wallet rechaza sin explicar.
 */
function derIa5String(value) {
  const bytes = new TextEncoder().encode(value);
  const len =
    bytes.length < 0x80
      ? [bytes.length]
      : (() => {
          const out = [];
          for (let n = bytes.length; n > 0; n = Math.floor(n / 256)) out.unshift(n % 256);
          return [0x80 | out.length, ...out];
        })();
  return new Uint8Array([0x16, ...len, ...bytes]).buffer;
}

/** certificatePolicies = [ { policyOid, [ cpsURI ] } ], serializada a extensión. */
function buildCertificatePolicies(policyOid, cpsUri) {
  const policies = new CertificatePolicies([
    new PolicyInformation({
      policyIdentifier: policyOid,
      policyQualifiers: [
        new PolicyQualifierInfo({
          policyQualifierId: id_qt_csp,
          qualifier: derIa5String(cpsUri), // el cpsURI, como IA5String
        }),
      ],
    }),
  ]);
  return new x509.Extension(
    '2.5.29.32',
    false,
    AsnConvert.serialize(policies),
  );
}

/** El perfil de la cláusula 6.6.1 convertido en test. */
export function assertWrpacProfile(certPem) {
  const cert = new x509.X509Certificate(certPem);
  const problems = [];
  const dn = new x509.Name(cert.subject);

  if (!dn.getField(OID_ORGANIZATION_IDENTIFIER)[0])
    problems.push('GEN-6.6.1-05: falta organizationIdentifier en el subject DN');
  if (!dn.getField('CN')[0]) problems.push('GEN-6.1.1-04: falta CommonName');

  const pol = cert.getExtension('2.5.29.32');
  if (!pol) problems.push('GEN-6.6.1-03: falta la extensión certificatePolicies');
  else {
    const parsed = AsnConvert.parse(pol.value, CertificatePolicies);
    const oids = parsed.map((p) => p.policyIdentifier);
    if (!oids.some((o) => Object.values(WRPAC_POLICY).includes(o)))
      problems.push(`GEN-6.6.1-03: ninguna política es de TS 119 411-8 (encontradas: ${oids.join(', ')})`);
    const hasCps = parsed.some((p) => p.policyQualifiers?.some((q) => q.policyQualifierId === id_qt_csp));
    if (!hasCps) problems.push('GEN-6.6.1-06: falta el qualifier cpsURI');
  }

  const san = cert.getExtension('2.5.29.17');
  if (!san) problems.push('GEN-6.6.1-07: falta el SAN con la información de contacto del RP');

  return problems;
}
