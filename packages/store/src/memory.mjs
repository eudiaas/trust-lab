// Almacen en memoria. Existe para la suite de conformidad: los tres
// adaptadores tienen que comportarse igual, y el de memoria es el que
// establece que significa "igual" sin depender de disco ni de SQL.
export function memoryStore() {
  const docs = new Map();
  const keys = new Map();
  const artifacts = [];
  const k = (kind, id) => `${kind}\u0000${id}`;

  return {
    kind: 'memory',
    docs: {
      async get(kind, id) {
        if (kind !== '*') return docs.get(k(kind, id)) ?? null;
        for (const [key, doc] of docs) if (key.split('\u0000')[1] === id) return doc;
        return null;
      },
      async put(kind, id, doc) {
        docs.set(k(kind, id), doc);
        return doc;
      },
      async list(kind) {
        return [...docs.entries()]
          .filter(([key]) => kind === '*' || key.startsWith(`${kind}\u0000`))
          .map(([key, doc]) => ({ id: key.split('\u0000')[1], ...doc }));
      },
      async delete(kind, id) {
        if (kind !== '*') return void docs.delete(k(kind, id));
        for (const key of [...docs.keys()]) if (key.split('\u0000')[1] === id) docs.delete(key);
      },
    },
    keys: {
      async get(name) {
        return keys.get(name) ?? null;
      },
      async put(name, doc) {
        keys.set(name, doc);
        return doc;
      },
      async list() {
        return [...keys.keys()];
      },
    },
    artifacts: {
      async put(a) {
        artifacts.push({ ...a, createdAt: new Date().toISOString() });
        return a;
      },
      async latest(kind, id) {
        return artifacts.filter((a) => a.kind === kind && a.id === id).at(-1) ?? null;
      },
      async get(kind, id, sequence) {
        return (
          artifacts.find((a) => a.kind === kind && a.id === id && a.sequence === sequence) ?? null
        );
      },
      async list(kind, id) {
        return artifacts.filter((a) => a.kind === kind && a.id === id);
      },
    },
  };
}
