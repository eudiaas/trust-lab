// Almacen SQL. Se escribe contra un puerto minimo `query(sql, params)`, asi que
// el mismo codigo corre sobre `pg` (Railway) y sobre PGlite (Postgres compilado
// a WASM, sin servidor) — que es como esta probado aqui: SQL de verdad, con sus
// restricciones de verdad, sin levantar nada.
//
// La diferencia de fondo con el almacen de fichero esta en `artifacts`: aqui NO
// hay git detras, asi que cada emision se guarda como una fila nueva e
// inmutable. Un artefacto firmado no se puede reconstruir a posteriori — la
// firma depende de la clave, del instante y del orden de serializacion — de
// modo que se guarda el byte, no la receta.

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS docs (
  kind        text NOT NULL,
  id          text NOT NULL,
  doc         jsonb NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, id)
);

CREATE TABLE IF NOT EXISTS keys (
  name        text PRIMARY KEY,
  doc         jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS artifacts (
  kind         text NOT NULL,
  id           text NOT NULL,
  sequence     integer NOT NULL,
  content_type text NOT NULL,
  body         text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, id, sequence)
);

ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS next_update timestamptz;
ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS signer text;
`;

export function sqlStore({ query, schema = SCHEMA_SQL, close }) {
  const q = (sql, params = []) => query(sql, params);

  return {
    kind: 'sql',

    // Sin esto un CLI que abre la conexion nunca termina: tanto un pool de
    // `pg` como PGlite mantienen vivo el event loop. Se nota como "el comando
    // se cuelga despues de hacer su trabajo", que es de los sintomas mas
    // desorientadores que hay.
    close: close ?? (() => {}),

    // El esquema se aplica sentencia a sentencia. No es cosmetica: el
    // protocolo extendido de Postgres —el que usan tanto `pg` con parametros
    // como PGlite siempre— rechaza varias sentencias en un mismo enunciado
    // preparado ("cannot insert multiple commands into a prepared statement").
    async migrate() {
      for (const stmt of schema.split(';').map((s) => s.trim()).filter(Boolean)) {
        await q(stmt);
      }
    },

    docs: {
      // El comodin '*' significa "de cualquier tipo", igual que en el
      // adaptador de fichero, donde el id ya es unico. Sin esto los dos
      // adaptadores no son intercambiables — y no lo eran: la suite de
      // conformidad solo probaba `get` con un kind concreto.
      async get(kind, id) {
        const r =
          kind === '*'
            ? await q('SELECT doc FROM docs WHERE id = $1', [id])
            : await q('SELECT doc FROM docs WHERE kind = $1 AND id = $2', [kind, id]);
        return r.rows[0]?.doc ?? null;
      },
      async put(kind, id, doc) {
        await q(
          `INSERT INTO docs (kind, id, doc) VALUES ($1, $2, $3)
           ON CONFLICT (kind, id) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()`,
          [kind, id, JSON.stringify(doc)],
        );
        return doc;
      },
      async list(kind) {
        const r =
          kind === '*'
            ? await q('SELECT id, doc FROM docs ORDER BY kind, id')
            : await q('SELECT id, doc FROM docs WHERE kind = $1 ORDER BY id', [kind]);
        return r.rows.map((row) => ({ id: row.id, ...row.doc }));
      },
      async delete(kind, id) {
        if (kind === '*') await q('DELETE FROM docs WHERE id = $1', [id]);
        else await q('DELETE FROM docs WHERE kind = $1 AND id = $2', [kind, id]);
      },
    },

    keys: {
      async get(name) {
        const r = await q('SELECT doc FROM keys WHERE name = $1', [name]);
        return r.rows[0]?.doc ?? null;
      },
      async put(name, doc) {
        await q(
          `INSERT INTO keys (name, doc) VALUES ($1, $2)
           ON CONFLICT (name) DO UPDATE SET doc = EXCLUDED.doc`,
          [name, JSON.stringify(doc)],
        );
        return doc;
      },
      async list() {
        const r = await q('SELECT name FROM keys ORDER BY name');
        return r.rows.map((row) => row.name);
      },
      async delete(name) {
        await q('DELETE FROM keys WHERE name = $1', [name]);
      },
    },

    artifacts: {
      // Sin ON CONFLICT a proposito: reemitir con la misma secuencia es un
      // error, no una actualizacion. Lo publicado no se reescribe.
      async put({ kind, id, sequence, contentType, body, nextUpdate, signer }) {
        await q(
          `INSERT INTO artifacts (kind, id, sequence, content_type, body, next_update, signer)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [kind, id, sequence, contentType, body, nextUpdate ?? null, signer ?? null],
        );
        return { kind, id, sequence, contentType, body, nextUpdate, signer };
      },
      async latest(kind, id) {
        const r = await q(
          `SELECT sequence, content_type, body, created_at, next_update, signer FROM artifacts
           WHERE kind = $1 AND id = $2 ORDER BY sequence DESC LIMIT 1`,
          [kind, id],
        );
        const row = r.rows[0];
        return row
          ? { kind, id, sequence: row.sequence, contentType: row.content_type, body: row.body, createdAt: row.created_at, nextUpdate: row.next_update, signer: row.signer }
          : null;
      },
      async get(kind, id, sequence) {
        const r = await q(
          `SELECT sequence, content_type, body, next_update, signer FROM artifacts
           WHERE kind = $1 AND id = $2 AND sequence = $3`,
          [kind, id, sequence],
        );
        const row = r.rows[0];
        return row
          ? { kind, id, sequence: row.sequence, contentType: row.content_type, body: row.body, nextUpdate: row.next_update, signer: row.signer }
          : null;
      },
      async list(kind, id) {
        const r = await q(
          `SELECT sequence, content_type, created_at, next_update FROM artifacts
           WHERE kind = $1 AND id = $2 ORDER BY sequence`,
          [kind, id],
        );
        return r.rows.map((row) => ({ kind, id, sequence: row.sequence, contentType: row.content_type, createdAt: row.created_at, nextUpdate: row.next_update }));
      },
      // Borra TODAS las versiones. Lo publicado no se reescribe, pero si se
      // retira: media version borrada dejaria el publisher sirviendo una
      // anterior, que es peor que no servir nada.
      async delete(kind, id) {
        await q('DELETE FROM artifacts WHERE kind = $1 AND id = $2', [kind, id]);
      },
    },
  };
}

/** Puerto sobre `pg` (Railway). */
export function pgQuery(pool) {
  return (sql, params) => pool.query(sql, params);
}

/** Puerto sobre PGlite (pruebas, y desarrollo local sin servidor). */
export function pgliteQuery(db) {
  return (sql, params) => db.query(sql, params);
}
