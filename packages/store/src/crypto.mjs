// Cifrado en reposo del material de clave.
//
// El patrón es el de `ZK_SESSION_KEY` en espuni y por la misma razón: sin la
// clave, **no se guarda en claro**, se falla. Un modo degradado "sin cifrado
// por comodidad" en una fábrica de CAs no es una mejora de DX, es una
// regresión.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export class KeyEncryptionRequiredError extends Error {
  constructor(where) {
    super(
      `${where} exige cifrado del material de clave y no hay clave configurada. ` +
        `Define TRUST_LAB_KEY con 32 bytes (64 hex o base64). Sin ella no se ` +
        `guardan claves privadas en claro.`,
    );
    this.name = 'KeyEncryptionRequiredError';
  }
}

/** Acepta 64 hex o base64; exige exactamente 32 bytes. */
export function parseKeyMaterial(value) {
  if (!value) return null;
  const buf = /^[0-9a-fA-F]{64}$/.test(value)
    ? Buffer.from(value, 'hex')
    : Buffer.from(value, 'base64');
  if (buf.length !== 32) {
    throw new Error(`TRUST_LAB_KEY debe ser de 32 bytes; llegaron ${buf.length}`);
  }
  return buf;
}

/**
 * Envuelve un almacén de claves para cifrar el campo privado (`key`) con
 * AES-256-GCM. El resto del documento —certificados, subject, nombre— queda en
 * claro a propósito: son públicos, y poder listarlos e inspeccionarlos sin
 * descifrar nada es justo lo que hace operable el almacén.
 */
export function encryptedKeys(keys, keyMaterial, { required = true, where = 'este almacén' } = {}) {
  const material = parseKeyMaterial(keyMaterial);
  if (!material) {
    if (required) throw new KeyEncryptionRequiredError(where);
    return keys;
  }

  return {
    async put(name, doc) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', material, iv);
      const enc = Buffer.concat([
        cipher.update(JSON.stringify(doc.key), 'utf8'),
        cipher.final(),
      ]);
      return keys.put(name, {
        ...doc,
        key: undefined,
        keyEnc: {
          alg: 'A256GCM',
          iv: iv.toString('base64'),
          tag: cipher.getAuthTag().toString('base64'),
          data: enc.toString('base64'),
        },
      });
    },

    async get(name) {
      const doc = await keys.get(name);
      if (!doc) return null;
      if (!doc.keyEnc) return doc; // material antiguo en claro: se lee igual
      const decipher = createDecipheriv(
        'aes-256-gcm',
        material,
        Buffer.from(doc.keyEnc.iv, 'base64'),
      );
      decipher.setAuthTag(Buffer.from(doc.keyEnc.tag, 'base64'));
      const dec = Buffer.concat([
        decipher.update(Buffer.from(doc.keyEnc.data, 'base64')),
        decipher.final(),
      ]);
      const { keyEnc, ...rest } = doc;
      return { ...rest, key: JSON.parse(dec.toString('utf8')) };
    },

    list: (...a) => keys.list(...a),
  };
}
