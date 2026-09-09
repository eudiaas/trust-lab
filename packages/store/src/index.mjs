// El almacen. Tres colecciones y nada mas:
//
//   docs      — el estado explicito (contrato 3): registros de RP, estado de
//               cada lista, estado de cada status list. Mutable, versionado
//               por su propio `sequenceNumber`.
//   keys      — material criptografico. Lo unico que hay que proteger.
//   artifacts — lo emitido y firmado. INMUTABLE: cada emision guarda su
//               JWS/XML integro, no solo el estado que lo genero.
//
// Esa ultima coleccion es deliberada. En la version de fichero, git respondia a
// "que decia la lista el 7 de septiembre" con un `git show`. Una base de datos
// lo perderia si solo guardara el estado actual, porque un artefacto firmado NO
// se puede reconstruir a posteriori: la firma depende de la clave, del instante
// y del orden de serializacion. Se guarda el byte, no la receta.
export { fileStore } from './file.mjs';
export { memoryStore } from './memory.mjs';
export { sqlStore, pgQuery, pgliteQuery, SCHEMA_SQL } from './sql.mjs';
export { openStore } from './open.mjs';
export { seedMissing } from './seed.mjs';
export { encryptedKeys, parseKeyMaterial, KeyEncryptionRequiredError } from './crypto.mjs';
