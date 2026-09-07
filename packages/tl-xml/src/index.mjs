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

  const providers = state.providers
    .map(
      (p) => `
   <TrustServiceProvider>
    <TSPInformation>
     <TSPName><Name xml:lang="en">${esc(p.name)}</Name></TSPName>
    </TSPInformation>
    <TSPServices>
     <TSPService>
      <ServiceInformation>
       <ServiceTypeIdentifier>${paa}</ServiceTypeIdentifier>
       <ServiceName><Name xml:lang="en">${esc(p.serviceName)}</Name></ServiceName>
       <ServiceDigitalIdentity>
        <DigitalId><X509Certificate>${pemToBase64Der(p.certPem)}</X509Certificate></DigitalId>
       </ServiceDigitalIdentity>
       <ServiceStatus>${p.status ?? recognized}</ServiceStatus>
       <StatusStartingTime>${iso(p.statusStartingTime ?? now)}</StatusStartingTime>
      </ServiceInformation>
     </TSPService>
    </TSPServices>
   </TrustServiceProvider>`,
    )
    .join('');

  return `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="${NS}" Id="TL" TSLTag="${TSL_TAG}">
 <SchemeInformation>
  <TSLVersionIdentifier>6</TSLVersionIdentifier>
  <TSLSequenceNumber>${state.sequenceNumber}</TSLSequenceNumber>
  <TSLType>${profile.tslType}</TSLType>
  <SchemeOperatorName><Name xml:lang="en">${esc(state.schemeOperatorName)}</Name></SchemeOperatorName>
  <SchemeName><Name xml:lang="en">${esc(state.schemeName)}</Name></SchemeName>
  <SchemeTerritory>${esc(state.territory ?? 'EU')}</SchemeTerritory>
  <StatusDeterminationApproach>${state.statusDeterminationApproach}</StatusDeterminationApproach>
  <ListIssueDateTime>${issued}</ListIssueDateTime>
  <NextUpdate><dateTime>${next}</dateTime></NextUpdate>
 </SchemeInformation>
 <TrustServiceProviderList>${providers}
 </TrustServiceProviderList>
</TrustServiceStatusList>`;
}

/**
 * Firma XAdES enveloped sobre el elemento raíz (Id="TL").
 *
 * El certificado del firmante va en ds:KeyInfo/X509Data, que es de donde
 * @owf/eudi-tl —y por tanto EUDIPLO y el camino ZK de espuni— lo saca para
 * comprobarlo contra el ancla pineada.
 */
export async function signTrustedListXml(xml, signer, crypto) {
  XAdES.Application.setEngine('NodeJS', crypto);
  setNodeDependencies({ DOMParser, XMLSerializer, DOMImplementation });

  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  const signed = new XAdES.SignedXml();
  const chain = signer.certificateChain.map(pemToBase64Der);

  await signed.Sign({ name: 'ECDSA', hash: 'SHA-256' }, signer.cryptoKey, doc, {
    references: [{ id: 'r0', uri: '#TL', hash: 'SHA-256', transforms: ['enveloped', 'c14n'] }],
    x509: chain,
    signingCertificate: chain[0],
  });
  return signed.toString();
}
