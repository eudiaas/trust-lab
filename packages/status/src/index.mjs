// Status lists — IETF Token Status List, sobre @owf/token-status-list.
//
// Es la pieza que convierte la revocación en algo comprobable: el WRPRC lleva
// un `status.status_list = { idx, uri }` (tabla de TS 119 475), y esa URI
// apunta aquí. Sin esto, "certificado de registro revocado" no es un caso de
// prueba, es una frase.
//
// Puro (contrato 1) y firma por `Signer` (contrato 2), como el resto.
import { StatusList, StatusType, createHeaderAndPayload, MediaTypes } from '@owf/token-status-list';
import { importX509, jwtVerify } from 'jose';
import { toBase64Url } from '../../signer/src/index.mjs';

export { StatusType, MediaTypes };

/** Nombres legibles ↔ valores del registro IETF. */
export const STATUS_BY_NAME = {
  valid: StatusType.Valid,
  invalid: StatusType.Invalid,
  suspended: StatusType.Suspended,
};

/**
 * Construye la lista desde el estado.
 *
 * `size` es el número de entradas y **no** se ajusta al número de referencias
 * emitidas a propósito: una lista que crece cada vez que se revoca algo filtra
 * cuántos certificados hay vivos. Se reserva de golpe y se rellena de ceros.
 */
export function buildStatusList(state) {
  const bits = state.bits ?? 1;
  const values = new Array(state.size ?? 1024).fill(StatusType.Valid);
  for (const [idx, entry] of Object.entries(state.entries ?? {})) {
    const value = STATUS_BY_NAME[entry.status];
    if (value === undefined) throw new Error(`estado desconocido en la posición ${idx}: ${entry.status}`);
    values[Number(idx)] = value;
  }
  return new StatusList(values, bits);
}

/**
 * Firma la lista como JWT compacto con `typ: statuslist+jwt`.
 *
 * `sub` tiene que ser la URI por la que se publica: es lo que ata la lista a su
 * localización e impide reutilizar una lista de otro sitio.
 */
export async function signStatusListCompact(state, signer, { issuedAt = new Date(), ttl } = {}) {
  const list = buildStatusList(state);
  const { header, payload } = createHeaderAndPayload(
    list,
    {
      sub: state.url,
      iat: Math.floor(issuedAt.getTime() / 1000),
      ...(ttl ? { ttl } : {}),
      ...(state.expiresInDays
        ? { exp: Math.floor(issuedAt.getTime() / 1000) + state.expiresInDays * 86_400 }
        : {}),
    },
    { alg: 'ES256', x5c: signer.certificateChain.map(stripPem) },
  );

  const signingInput = `${toBase64Url(JSON.stringify(header))}.${toBase64Url(JSON.stringify(payload))}`;
  const signature = await signer.sign(signingInput);
  return `${signingInput}.${toBase64Url(signature)}`;
}

const stripPem = (pem) =>
  pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, '');

/**
 * Lee la lista de vuelta como lo haría un verificador: comprueba la firma
 * contra el certificado del emisor y devuelve el estado de una posición.
 */
export async function readStatus(compactJwt, signerCertPem, idx) {
  const key = await importX509(signerCertPem, 'ES256');
  const { payload, protectedHeader } = await jwtVerify(compactJwt, key, { clockTolerance: 300 });
  if (protectedHeader.typ !== 'statuslist+jwt') {
    throw new Error(`typ inesperado: ${protectedHeader.typ}`);
  }
  const bytes = Uint8Array.from(Buffer.from(payload.status_list.lst, 'base64url'));
  const list = StatusList.decompressStatusListFromBytes(bytes, payload.status_list.bits);
  const value = list.getStatus(idx);
  return {
    sub: payload.sub,
    bits: payload.status_list.bits,
    value,
    status: Object.keys(STATUS_BY_NAME).find((k) => STATUS_BY_NAME[k] === value) ?? `desconocido(${value})`,
  };
}
