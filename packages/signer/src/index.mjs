// Contrato 2: toda firma pasa por esta interfaz.
//
//   sign(bytes) -> Uint8Array
//   certificateChain -> string[]  (PEM, hoja primero)
//
// En C la implementación lee un PEM del disco. En B será KMS/Vault/BD, y
// ningún paquete de arriba se entera: es el mismo patrón que usan
// `signWRPRC({ signer })` de @owf/eudi-wrprc y el KMS de EUDIPLO.
//
// Este fichero NO toca disco a propósito (contrato 1): recibe el material ya
// leído. Quien lee ficheros es el CLI.

/** @typedef {{ sign(data: Uint8Array): Promise<Uint8Array>, alg: string, certificateChain: string[], cryptoKey?: CryptoKey }} Signer */

/**
 * Signer respaldado por una clave en memoria (WebCrypto).
 * @param {CryptoKey} privateKey
 * @param {string[]} certificateChain PEM, hoja primero
 * @param {Crypto} crypto
 * @returns {Signer}
 */
export function inMemorySigner(privateKey, certificateChain, crypto) {
  return {
    alg: 'ES256',
    certificateChain,
    cryptoKey: privateKey,
    async sign(data) {
      // Los consumidores no coinciden en qué entregan: xadesjs pasa bytes y
      // `signLoTE` pasa el signing input del JWS como string. Normalizar aquí
      // —y no en cada llamador— es lo que mantiene la interfaz de una pieza.
      const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
      const sig = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        privateKey,
        bytes,
      );
      return new Uint8Array(sig);
    },
  };
}

/** PEM → base64 DER (sin cabeceras), que es como viajan los certs en TSL y LoTE. */
export function pemToBase64Der(pem) {
  return pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

/** base64url sin relleno — el encaje habitual de una firma en JOSE. */
export function toBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}
