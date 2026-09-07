// Siembra inicial: los documentos de estado versionados en el repo entran en el
// almacen la primera vez que arranca contra una base de datos vacia.
//
// Hace falta porque el estado vive en dos sitios con papeles distintos: en git
// como plantilla revisable, y en el almacen como lo que de verdad se emite. Sin
// esto, un despliegue nuevo presenta una consola vacia y el operador no tiene
// por donde empezar.
//
// Solo siembra lo que NO existe, asi que es idempotente y nunca pisa lo que el
// operador haya cambiado en produccion.
import { fileStore } from './file.mjs';

export async function seedIfEmpty(store, root) {
  if (store.kind === 'file') return { seeded: [], reason: 'el almacen ya es el de fichero' };

  const existing = await store.docs.list('*');
  if (existing.length) return { seeded: [], reason: 'el almacen ya tiene documentos' };

  const repo = fileStore({ root });
  const docs = await repo.docs.list('*');
  const seeded = [];
  for (const { id, ...doc } of docs) {
    await store.docs.put(doc.kind ?? 'doc', id, doc);
    seeded.push(id);
  }
  return { seeded, reason: seeded.length ? 'sembrado desde state/' : 'no hay nada que sembrar' };
}
