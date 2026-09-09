// Siembra inicial: los documentos de estado versionados en el repo entran en el
// almacen la primera vez que arranca contra una base de datos vacia.
//
// Hace falta porque el estado vive en dos sitios con papeles distintos: en git
// como plantilla revisable, y en el almacen como lo que de verdad se emite. Sin
// esto, un despliegue nuevo presenta una consola vacia y el operador no tiene
// por donde empezar.
//
// Siembra DOCUMENTO A DOCUMENTO los que falten, y solo esos: es idempotente y
// nunca pisa lo que el operador haya cambiado en produccion.
//
// Antes comprobaba `if (existing.length) return` —o sea, sembraba solo contra un
// almacen entero vacio— pese a que este comentario ya prometia lo contrario. La
// diferencia no es teorica: al anadir `pubeaa-lab` al repo, ningun despliegue con
// documentos previos lo habria recibido nunca, y el dashboard lo pintaba como
// "no existe" sin ofrecer forma de crearlo salvo un reset destructivo. Una lista
// nueva llega con el codigo; tiene que llegar tambien al almacen.
import { fileStore } from './file.mjs';

export async function seedMissing(store, root) {
  if (store.kind === 'file') return { seeded: [], reason: 'el almacen ya es el de fichero' };

  const existing = new Set((await store.docs.list('*')).map((d) => d.id));
  const repo = fileStore({ root });
  const docs = await repo.docs.list('*');
  const seeded = [];
  for (const { id, ...doc } of docs) {
    if (existing.has(id)) continue;
    await store.docs.put(doc.kind ?? 'doc', id, doc);
    seeded.push(id);
  }
  return {
    seeded,
    reason: seeded.length ? 'sembrado desde state/' : 'el almacen ya tiene todos los documentos',
  };
}
