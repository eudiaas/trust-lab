// Listas de confianza ETSI TS 119 612 (XML + XAdES) — el formato de la EU AV
// Trusted List. Es lo único que NO da ninguna librería: @owf/eudi-tl parsea,
// valida y VERIFICA firmas, pero no las produce. Aquí se produce.
//
// Puro (contrato 1): recibe el estado y un Signer, devuelve una cadena XML.
// Quien lee y escribe ficheros es el CLI.
import 'reflect-metadata';
import * as XAdES from 'xadesjs';
import { DOMParser, XMLSerializer, DOMImplementation } from '@xmldom/xmldom';
import { setNodeDependencies } from 'xml-core';
import { pemToBase64Der } from '../../signer/src/index.mjs';

// El vocabulario del perfil AV lo publica @owf/eudi-tl en TrustedListProfiles
// .ageVerification, así que no se copia a mano: se importa de la misma
// librería que luego lo valida. Si cambia, cambia en los dos lados a la vez.
export { TrustedListProfiles } from '@owf/eudi-tl';

const NS = 'http://uri.etsi.org/02231/v2#';
const NS_ADDTYPES = 'http://uri.etsi.org/02231/v2/additionaltypes#';
const TSL_TAG = 'http://uri.etsi.org/19612/TSLTag';

const iso = (d) => new Date(d).toISOString().replace(/\.\d+Z$/, 'Z');
const esc = (s) =>
  String(s).replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' })[c]);

/**
 * Construye el XML (sin firmar) de una Trusted List del perfil AV.
 *
 * @param {object} state         el documento de estado del entorno (contrato 3)
 * @param {string} state.schemeOperatorName
 * @param {string} state.schemeName
 * @param {number} state.sequenceNumber   se incrementa en cada emisión
 * @param {string} state.territory        ISO 3166-1 alpha-2, o "EU"
 * @param {number} state.validityDays     de aquí sale NextUpdate
 * @param {Array<{name:string,serviceName:string,certPem:string,status?:string}>} state.providers
 * @param {object} profile       TrustedListProfiles.ageVerification
 */
export function buildTrustedListXml(state, profile, now = new Date()) {
  const issued = iso(now);
  const next = iso(now.getTime() + (state.validityDays ?? 30) * 86_400_000);
  const recognized = profile.serviceStatuses[0];
  const paa = profile.serviceTypes[0];
  const lang = state.lang ?? 'en';
  const ml = (tag, v) => `<${tag}><Name xml:lang="${lang}">${esc(v)}</Name></${tag}>`;
  const uris = (tag, list) =>
    `<${tag}>${list.map((u) => `<URI xml:lang="${lang}">${esc(u)}</URI>`).join('')}</${tag}>`;

  // 5.3.5 / 5.4.3: dirección postal + electrónica, ambas obligatorias.
  const address = (a) => `<PostalAddresses><PostalAddress xml:lang="${lang}">` +
    `<StreetAddress>${esc(a.street)}</StreetAddress>` +
    `<Locality>${esc(a.locality)}</Locality>` +
    `<PostalCode>${esc(a.postalCode)}</PostalCode>` +
    `<CountryName>${esc(a.country)}</CountryName>` +
    `</PostalAddress></PostalAddresses>` +
    `<ElectronicAddress>${a.uris.map((u) => `<URI xml:lang="${lang}">${esc(u)}</URI>`).join('')}</ElectronicAddress>`;

  // 5.3.13 + tabla I.1 del perfil AV: "Value: Pointer to itself". El tuple lleva
  // la localización, la identidad digital del firmante de la lista apuntada, y
  // los TL Qualifiers (TSLType, scheme operator name, scheme rules, territorio
  // y mime type de la cláusula 6.2).
  const pointer = state.pointerToSelf
    ? `<PointersToOtherTSL><OtherTSLPointer>` +
      `<ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId>` +
      `<X509Certificate>${pemToBase64Der(state.pointerToSelf.signerCertPem)}</X509Certificate>` +
      `</DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>` +
      `<TSLLocation>${esc(state.url)}</TSLLocation>` +
      `<AdditionalInformation>` +
      `<OtherInformation><TSLType>${profile.tslType}</TSLType></OtherInformation>` +
      `<OtherInformation>${ml('SchemeOperatorName', state.schemeOperatorName)}</OtherInformation>` +
      `<OtherInformation>${uris('SchemeTypeCommunityRules', state.schemeTypeCommunityRules)}</OtherInformation>` +
      `<OtherInformation><ns3:SchemeTerritory xmlns:ns3="${NS_ADDTYPES}">${esc(state.territory)}</ns3:SchemeTerritory></OtherInformation>` +
      `<OtherInformation><ns3:MimeType xmlns:ns3="${NS_ADDTYPES}">${esc(state.pointerToSelf.mimeType)}</ns3:MimeType></OtherInformation>` +
      `</AdditionalInformation></OtherTSLPointer></PointersToOtherTSL>`
    : '';

  const providers = state.providers
    .map((p) => `
   <TrustServiceProvider>
    <TSPInformation>
     ${ml('TSPName', p.name)}
     ${ml('TSPTradeName', p.tradeName ?? p.name)}
     <TSPAddress>${address(p.address ?? state.address)}</TSPAddress>
     ${uris('TSPInformationURI', p.informationUri)}
    </TSPInformation>
    <TSPServices>
     <TSPService>
      <ServiceInformation>
       <ServiceTypeIdentifier>${paa}</ServiceTypeIdentifier>
       ${ml('ServiceName', p.serviceName)}
       <ServiceDigitalIdentity>
        <DigitalId><X509Certificate>${pemToBase64Der(p.certPem)}</X509Certificate></DigitalId>
       </ServiceDigitalIdentity>
       <ServiceStatus>${p.status ?? recognized}</ServiceStatus>
       <StatusStartingTime>${iso(p.statusStartingTime ?? now)}</StatusStartingTime>
      </ServiceInformation>
     </TSPService>
    </TSPServices>
   </TrustServiceProvider>`)
    .join('');

  // El orden de los hijos de SchemeInformation NO es libre: lo fija el schema
  // XML del anexo C. Esta secuencia es la de la tabla de la cláusula 5.
  return `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="${NS}" Id="TL" TSLTag="${TSL_TAG}">
 <SchemeInformation>
  <TSLVersionIdentifier>6</TSLVersionIdentifier>
  <TSLSequenceNumber>${state.sequenceNumber}</TSLSequenceNumber>
  <TSLType>${profile.tslType}</TSLType>
  ${ml('SchemeOperatorName', state.schemeOperatorName)}
  <SchemeOperatorAddress>${address(state.address)}</SchemeOperatorAddress>
  ${ml('SchemeName', state.schemeName)}
  ${uris('SchemeInformationURI', state.schemeInformationUri)}
  <StatusDeterminationApproach>${state.statusDeterminationApproach}</StatusDeterminationApproach>
  ${uris('SchemeTypeCommunityRules', state.schemeTypeCommunityRules)}
  <SchemeTerritory>${esc(state.territory)}</SchemeTerritory>
  <PolicyOrLegalnotice>${state.legalNotice
    .map((n) => `<TSLLegalNotice xml:lang="${lang}">${esc(n)}</TSLLegalNotice>`)
    .join('')}</PolicyOrLegalnotice>
  <HistoricalInformationPeriod>${state.historicalInformationPeriodDays ?? 65535}</HistoricalInformationPeriod>
  ${pointer}
  <ListIssueDateTime>${issued}</ListIssueDateTime>
  <NextUpdate><dateTime>${next}</dateTime></NextUpdate>
 </SchemeInformation>
 <TrustServiceProviderList>${providers}
 </TrustServiceProviderList>
</TrustServiceStatusList>`;
}

/**
 * Firma XAdES enveloped conforme al **Annex B (normativo) de TS 119 612 v2.3.1**.
 *
 * B.1.0 impone cuatro reglas que no son las que xadesjs hace por defecto:
 *   1) firma enveloped;
 *   2) un ds:Reference al TrustServiceStatusList con UN solo ds:Transforms que
 *      contenga DOS ds:Transform: enveloped-signature y **exclusive** c14n;
 *   3) ds:CanonicalizationMethod = exclusive c14n;
 *   4) puede llevar más referencias (ahí entran las propiedades XAdES).
 * Y B.1.1 exige `xades:SigningCertificateV2` — no la V1, que es lo que emite
 * xadesjs si le pasas `signingCertificate`.
 *
 * El certificado del firmante va en ds:KeyInfo/X509Data, que es de donde
 * @owf/eudi-tl —y por tanto EUDIPLO y el camino ZK de espuni— lo saca para
 * comprobarlo contra el ancla pineada.
 */
export const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

export async function signTrustedListXml(xml, signer, crypto) {
  XAdES.Application.setEngine('NodeJS', crypto);
  setNodeDependencies({ DOMParser, XMLSerializer, DOMImplementation });

  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  const signed = new XAdES.SignedXml();
  const chain = signer.certificateChain.map(pemToBase64Der);

  // B.1.0 regla 3: xadesjs pone c14n inclusiva por defecto y no hay opción
  // para cambiarlo, así que se fija en el objeto antes de firmar.
  signed.XmlSignature.SignedInfo.CanonicalizationMethod.Algorithm = EXC_C14N;

  await signed.Sign({ name: 'ECDSA', hash: 'SHA-256' }, signer.cryptoKey, doc, {
    // B.1.0 regla 2: enveloped + exclusive c14n, en ese orden.
    references: [{ id: 'r0', uri: '#TL', hash: 'SHA-256', transforms: ['enveloped', 'exc-c14n'] }],
    x509: chain,
    signingCertificateV2: chain[0],   // B.1.1
    signingTime: {},
  });
  return signed.toString();
}

/**
 * Comprueba el Annex B sobre el XML ya firmado. Es la norma convertida en test:
 * si xadesjs cambia un default, esto lo caza antes que una wallet.
 */
export function assertAnnexB(signedXml) {
  const problems = [];
  const sig = signedXml.slice(signedXml.indexOf('<ds:Signature'));
  const canon = /<ds:CanonicalizationMethod Algorithm="([^"]+)"/.exec(sig)?.[1];
  if (canon !== EXC_C14N) problems.push(`B.1.0(3): CanonicalizationMethod es ${canon}, debe ser exclusive c14n`);

  const transforms = /<ds:Reference[^>]*URI="#TL"[^>]*>\s*<ds:Transforms>([\s\S]*?)<\/ds:Transforms>/.exec(sig);
  if (!transforms) problems.push('B.1.0(2): no hay ds:Reference a #TL con ds:Transforms');
  else {
    const algs = [...transforms[1].matchAll(/Algorithm="([^"]+)"/g)].map((m) => m[1]);
    if (algs.length !== 2) problems.push(`B.1.0(2b): ${algs.length} transforms, deben ser 2`);
    if (algs[0] !== 'http://www.w3.org/2000/09/xmldsig#enveloped-signature')
      problems.push(`B.1.0(2b): la 1ª transform debe ser enveloped-signature, es ${algs[0]}`);
    if (algs[1] !== EXC_C14N)
      problems.push(`B.1.0(2b): la 2ª transform debe ser exclusive c14n, es ${algs[1]}`);
  }

  if (!/<xades:SigningCertificateV2>/.test(sig))
    problems.push('B.1.1: falta xades:SigningCertificateV2 (¿se emitió la V1?)');

  return problems;
}
