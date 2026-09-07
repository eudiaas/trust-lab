// Suite de conformidad: los tres adaptadores tienen que comportarse igual.
// Se ejecuta contra memoria, fichero y **Postgres de verdad** (PGlite, el
// motor compilado a WASM), asi que el SQL esta probado con sus restricciones
// reales sin levantar un servidor.
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { memoryStore, fileStore, sqlStore, pgliteQuery, encryptedKeys, KeyEncryptionRequiredError } from '../src/index.mjs';

let failures = 0;
const check = (name, cond, detail = '') => {
  if (cond) console.log(`  ok   ${name}`);
  else { failures++; console.log(`  FALLO ${name} ${detail}`); }
};
const eq = (name, a, b) => check(name, JSON.stringify(a) === JSON.stringify(b), `\n       ${JSON.stringify(a)}\n       ${JSON.stringify(b)}`);

async function conformance(store, { historial }) {
  console.log(`\n== ${store.kind} ==`);
  if (store.migrate) await store.migrate();

  await store.docs.put('list', 'av-lab', { kind: 'list', sequenceNumber: 1, providers: [] });
  eq('docs: leer lo escrito', (await store.docs.get('list', 'av-lab')).sequenceNumber, 1);
  await store.docs.put('list', 'av-lab', { kind: 'list', sequenceNumber: 2, providers: [] });
  eq('docs: sobrescribir', (await store.docs.get('list', 'av-lab')).sequenceNumber, 2);
  check('docs: inexistente da null', (await store.docs.get('list', 'no-existe')) === null);
  // El CLI busca por id sin saber el kind. Que el adaptador de fichero lo
  // permitiera y el SQL no fue justo el fallo que esta suite no vio.
  eq('docs: get con comodin "*"', (await store.docs.get('*', 'av-lab')).sequenceNumber, 2);
  check('docs: comodin con id inexistente da null', (await store.docs.get('*', 'no-existe')) === null);
  await store.docs.put('registry', 'espuni', { kind: 'registry' });
  const listado = await store.docs.list('list');
  check('docs: list filtra por kind', listado.length === 1 && listado[0].id === 'av-lab', JSON.stringify(listado));

  await store.keys.put('tl-signer', { name: 'tl-signer', key: { d: 'secreto' }, crt: ['PEM'] });
  eq('keys: leer lo escrito', (await store.keys.get('tl-signer')).key, { d: 'secreto' });
  check('keys: list', (await store.keys.list()).includes('tl-signer'));

  await store.artifacts.put({ kind: 'lists', id: 'av-lab', sequence: 1, contentType: 'application/vnd.etsi.tsl+xml', body: '<TL v1/>' });
  await store.artifacts.put({ kind: 'lists', id: 'av-lab', sequence: 2, contentType: 'application/vnd.etsi.tsl+xml', body: '<TL v2/>' });
  eq('artifacts: latest es la ultima', (await store.artifacts.latest('lists', 'av-lab')).body, '<TL v2/>');
  if (historial) {
    eq('artifacts: la version 1 sigue ahi', (await store.artifacts.get('lists', 'av-lab', 1)).body, '<TL v1/>');
    eq('artifacts: historial completo', (await store.artifacts.list('lists', 'av-lab')).length, 2);
  } else {
    console.log('  --   historial de artefactos: lo lleva git (almacen de fichero)');
  }

  // Borrado. Es la mitad que faltaba: sin el, el unico modo de deshacer una
  // emision mal encadenada era tirar el almacen entero.
  eq('artifacts: el firmante se conserva',
    (await store.artifacts.latest('lists', 'av-lab')).signer ?? null, null);
  await store.artifacts.put({ kind: 'lists', id: 'tmp', sequence: 1, contentType: 'text/plain', body: 'x', signer: 'tl-signer' });
  eq('artifacts: put guarda el firmante', (await store.artifacts.latest('lists', 'tmp')).signer, 'tl-signer');
  await store.artifacts.delete('lists', 'tmp');
  eq('artifacts: delete borra todas las versiones', await store.artifacts.latest('lists', 'tmp'), null);

  await store.keys.put('temporal', { name: 'temporal', key: {}, crt: [] });
  await store.keys.delete('temporal');
  eq('keys: delete', await store.keys.get('temporal'), null);
  check('keys: delete lo saca del listado', !(await store.keys.list()).includes('temporal'));
}

console.log('SUITE DE CONFORMIDAD DEL ALMACEN');
await conformance(memoryStore(), { historial: true });

const dir = await mkdtemp(join(tmpdir(), 'trust-lab-store-'));
await conformance(fileStore({ root: dir }), { historial: false });
await rm(dir, { recursive: true, force: true });

const { PGlite } = await import('@electric-sql/pglite');
const db = await PGlite.create();
const sql = sqlStore({ query: pgliteQuery(db) });
await conformance(sql, { historial: true });

console.log('\n== cifrado del material de clave ==');
const material = randomBytes(32).toString('hex');
const base = memoryStore();
const enc = encryptedKeys(base.keys, material, { where: 'el almacen de prueba' });
await enc.put('ca', { name: 'ca', key: { d: 'clave-privada' }, crt: ['PEM'] });
const crudo = await base.keys.get('ca');
check('la privada NO esta en claro en el almacen', JSON.stringify(crudo).includes('clave-privada') === false, JSON.stringify(crudo).slice(0, 120));
check('los certificados SI siguen legibles sin descifrar', crudo.crt[0] === 'PEM');
eq('descifrado devuelve la clave original', (await enc.get('ca')).key, { d: 'clave-privada' });

try {
  encryptedKeys(base.keys, undefined, { where: 'el almacen SQL' });
  check('sin clave configurada falla cerrado', false, '(no lanzo)');
} catch (err) {
  check('sin clave configurada falla cerrado', err instanceof KeyEncryptionRequiredError);
}

const otra = encryptedKeys(base.keys, randomBytes(32).toString('hex'));
try {
  await otra.get('ca');
  check('con otra clave no descifra', false, '(descifro igualmente)');
} catch {
  check('con otra clave no descifra', true);
}

// Guarda de compatibilidad: el material antiguo, escrito en claro por el CLI,
// se tiene que poder seguir leyendo tras activar el cifrado.
await base.keys.put('vieja', { name: 'vieja', key: { d: 'en-claro' }, crt: ['PEM'] });
eq('lee material antiguo sin cifrar', (await enc.get('vieja')).key, { d: 'en-claro' });

// El envoltorio tiene que exponer la MISMA interfaz que envuelve. `delete`
// faltaba, y no se noto hasta intentar borrar una clave sin dependencias.
await enc.delete('vieja');
eq('el envoltorio de cifrado tambien borra', await enc.get('vieja'), null);

console.log(failures === 0 ? '\nTODO OK' : `\n${failures} FALLO(S)`);
process.exit(failures === 0 ? 0 : 1);
