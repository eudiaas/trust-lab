// Apertura del almacen desde el entorno. La comparten el CLI, el publisher y la
// consola: si cada uno decidiera por su cuenta de donde sale el estado, acabaria
// habiendo tres respuestas distintas a la misma pregunta.
import { fileStore } from './file.mjs';
import { sqlStore, pgQuery, pgliteQuery } from './sql.mjs';
import { encryptedKeys } from './crypto.mjs';

/**
 * @param {object} opts
 * @param {string} opts.root  raiz del repo, para el almacen de fichero
 * @param {boolean} opts.needsKeys  si el proceso va a leer o escribir claves
 *   privadas. El publisher pasa `false`: sirve bytes ya firmados, asi que ni
 *   abre el material privado ni pide TRUST_LAB_KEY. Es la propiedad que hace
 *   que desplegarlo de cara a internet no exponga ninguna clave.
 */
export async function openStore({ root, needsKeys = true } = {}) {
  const withKeys = (store, where) => {
    if (!needsKeys) return store;
    if (store.kind === 'sql' || process.env.TRUST_LAB_KEY) {
      // `rawKeys` conserva el acceso SIN descifrar. Lo necesita la consola para
      // poder decir "esta clave esta cifrada" en un listado sin descifrar ni
      // una: mostrar el estado del material no deberia exigir tocarlo.
      store.rawKeys = store.keys;
      store.keys = encryptedKeys(store.keys, process.env.TRUST_LAB_KEY, { where });
    }
    return store;
  };

  // PGlite: Postgres compilado a WASM, sin servidor. Mismo SQL que Railway, asi
  // que el camino SQL se ejercita en local y en CI sin levantar nada.
  if (process.env.TRUST_LAB_PGLITE) {
    const { PGlite } = await import('@electric-sql/pglite');
    const db = await PGlite.create(process.env.TRUST_LAB_PGLITE);
    const store = sqlStore({ query: pgliteQuery(db), close: () => db.close() });
    await store.migrate();
    return withKeys(store, 'el almacen SQL');
  }

  if (process.env.DATABASE_URL) {
    const { default: pg } = await import('pg');
    const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
    const store = sqlStore({ query: pgQuery(pool), close: () => pool.end() });
    await store.migrate();
    return withKeys(store, 'el almacen SQL');
  }

  // En Railway el sistema de ficheros es efimero y cada servicio tiene el suyo:
  // caer al almacen de fichero ahi no daria un error, daria algo peor — la
  // consola escribiria en un disco que el publisher no ve, y todo se perderia
  // en el siguiente despliegue. Como el pin ES la clave y la URL viaja dentro
  // de artefactos firmados, eso no se recupera reemitiendo.
  if (process.env.RAILWAY_ENVIRONMENT_NAME || process.env.RAILWAY_ENVIRONMENT) {
    throw new Error(
      'falta DATABASE_URL. En Railway el disco es efimero y no se comparte entre ' +
        'servicios: el almacen de fichero perderia las claves en cada despliegue y ' +
        'el publisher no veria lo que emite la consola. Anade el plugin de Postgres.',
    );
  }

  return withKeys(fileStore({ root }), 'el almacen de fichero');
}
