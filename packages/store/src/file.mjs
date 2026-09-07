// Almacen de fichero: la disposicion que ya tenia el CLI, sin cambiar nada.
// `state/<id>.json`, `out/keys/<name>.json`, `out/<kind>/<id>.<ext>`.
//
// Se conserva byte a byte a proposito: el adaptador se prueba primero contra
// algo que ya sabemos que funciona, y asi un fallo del adaptador se distingue
// de un fallo del resto.
import { readFile, writeFile, mkdir, readdir, unlink } from 'node:fs/promises';
import { join, dirname } from 'node:path';

const EXT = { lists: 'xml', lote: 'json', status: 'jwt', wrprc: 'jwt' };

async function readJson(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

async function writeFileEnsuring(path, body) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, body);
}

export function fileStore({ root, artifactExt = EXT } = {}) {
  const statePath = (id) => join(root, 'state', `${id}.json`);
  const keyPath = (name) => join(root, 'out/keys', `${name}.json`);
  const artifactPath = (kind, id, ext) => join(root, 'out', kind, `${id}.${ext}`);

  return {
    kind: 'file',
    docs: {
      get: (_kind, id) => readJson(statePath(id)),
      async put(_kind, id, doc) {
        await writeFileEnsuring(statePath(id), JSON.stringify(doc, null, 2) + '\n');
        return doc;
      },
      async list(kind) {
        const files = await readdir(join(root, 'state')).catch(() => []);
        const docs = [];
        for (const f of files.filter((f) => f.endsWith('.json'))) {
          const doc = await readJson(join(root, 'state', f));
          if (doc && (!kind || kind === '*' || doc.kind === kind)) {
            docs.push({ id: f.replace(/\.json$/, ''), ...doc });
          }
        }
        return docs;
      },
      delete: (_kind, id) => unlink(statePath(id)).catch(() => {}),
    },

    keys: {
      get: (name) => readJson(keyPath(name)),
      async put(name, doc) {
        await writeFileEnsuring(keyPath(name), JSON.stringify(doc, null, 2) + '\n');
        return doc;
      },
      async list() {
        const files = await readdir(join(root, 'out/keys')).catch(() => []);
        return files.filter((f) => f.endsWith('.json')).map((f) => f.replace(/\.json$/, ''));
      },
      delete: (name) => unlink(keyPath(name)).catch(() => {}),
    },

    artifacts: {
      // En fichero solo vive LA ULTIMA emision, y el historial lo lleva git.
      // Es la asimetria deliberada con el almacen SQL, que si guarda todas las
      // versiones porque alli no hay git detras.
      async put({ kind, id, body, sequence, contentType, nextUpdate, signer }) {
        const ext = artifactExt[kind] ?? 'txt';
        const path = artifactPath(kind, id, ext);
        await writeFileEnsuring(path, body);
        // Los metadatos van a un `.meta.json` al lado: el publisher los
        // necesita (Content-Type, caducidad) y reparsear el artefacto para
        // deducirlos seria adivinar lo que ya sabiamos al emitirlo.
        await writeFileEnsuring(
          `${path}.meta.json`,
          JSON.stringify({ kind, id, sequence, contentType, nextUpdate, signer }, null, 2) + '\n',
        );
        return { kind, id, path, sequence, contentType, nextUpdate, signer };
      },
      async latest(kind, id) {
        const ext = artifactExt[kind] ?? 'txt';
        const path = artifactPath(kind, id, ext);
        const body = await readFile(path, 'utf8').catch(() => null);
        if (body === null) return null;
        const meta = (await readJson(`${path}.meta.json`)) ?? {};
        return { kind, id, body, ...meta };
      },
      async get(kind, id) {
        return this.latest(kind, id);
      },
      async list(kind, id) {
        const one = await this.latest(kind, id);
        return one ? [one] : [];
      },
      async delete(kind, id) {
        const path = artifactPath(kind, id, artifactExt[kind] ?? 'txt');
        await unlink(path).catch(() => {});
        await unlink(`${path}.meta.json`).catch(() => {});
      },
    },
  };
}
