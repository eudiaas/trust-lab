// Andamiaje comun de las suites end-to-end.
//
// Las tres —CLI, publisher y consola— necesitan lo mismo: un marco de
// confianza de verdad sobre el que operar, y que ese marco no sea el del
// operador. Asi que cada suite trabaja sobre una raiz temporal —copia de
// `apps/`, `packages/` y `state/`, con `node_modules` enlazado— y con el
// entorno limpio de `DATABASE_URL` y `TRUST_LAB_PGLITE`: un test que
// escribiera en el Postgres de produccion seria peor que no tenerlo.
//
// El almacen se elige por suite y no por comodidad: la consola corre contra
// **SQL** (PGlite, Postgres compilado a WASM) porque ahi es donde vive la clase
// de fallo que el almacen de fichero esconde — la clave primaria `(kind, id)` y
// el `id` que el documento no lleva dentro. El publisher corre contra fichero,
// que es lo que ejercita el CLI al construirle los artefactos.
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtempSync, rmSync, cpSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { randomBytes } from 'node:crypto';

export const ROOT = join(dirname(new URL(import.meta.url).pathname), '..');

/** Cuenta fallos y los imprime igual en las tres suites. */
export function contador() {
  const estado = { fallos: 0 };
  const check = (nombre, cond, detalle = '') => {
    if (cond) console.log(`  ok   ${nombre}`);
    else {
      estado.fallos += 1;
      console.log(`  FALLO ${nombre}${detalle ? '\n       ' + String(detalle).trim().split('\n').join('\n       ') : ''}`);
    }
  };
  const fin = () => {
    console.log(estado.fallos ? `\n${estado.fallos} FALLO(S)` : '\nTODO OK');
    process.exit(estado.fallos ? 1 : 0);
  };
  return { check, fin, estado };
}

/**
 * Raiz temporal con el repo dentro. `apps/` y `packages/` se COPIAN, no se
 * enlazan: el CLI y los servidores derivan su raiz de su propia ruta, asi que
 * un enlace los devolveria al repo de verdad y escribirian ahi.
 */
export function crearSandbox({ pglite = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'trustlab-e2e-'));
  for (const sub of ['apps', 'packages', 'state']) {
    cpSync(join(ROOT, sub), join(dir, sub), { recursive: true });
  }
  symlinkSync(join(ROOT, 'node_modules'), join(dir, 'node_modules'));

  const env = { ...process.env, TRUST_LAB_KEY: randomBytes(32).toString('hex') };
  delete env.DATABASE_URL;
  delete env.TRUST_LAB_PGLITE;
  delete env.RAILWAY_ENVIRONMENT_NAME;
  delete env.RAILWAY_ENVIRONMENT;
  delete env.CONSOLE_PASSWORD;
  delete env.PORT;
  if (pglite) env.TRUST_LAB_PGLITE = join(dir, 'pgdata');

  return { dir, env, limpiar: () => rmSync(dir, { recursive: true, force: true }) };
}

/** El CLI como lo ejecutaria un operador: proceso aparte, argv y salida. */
export function cli(sandbox, ...args) {
  const r = spawnSync(process.execPath, ['apps/cli/index.mjs', ...args], {
    cwd: sandbox.dir, env: sandbox.env, encoding: 'utf8',
  });
  return { code: r.status, out: r.stdout ?? '', err: r.stderr ?? '', args };
}

const puertoLibre = () =>
  new Promise((resolve, reject) => {
    const s = createServer();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

/**
 * Arranca uno de los servicios y espera a que responda.
 *
 * Devuelve tambien lo que escribio en stdout/stderr: los dos servicios dicen
 * cosas que importan al arrancar (que almacen abrieron, si sembraron, si
 * alguien confundio consola con publisher), y eso solo se puede comprobar
 * leyendolo.
 */
export async function arrancar(sandbox, app, extraEnv = {}) {
  const port = await puertoLibre();
  const proc = spawn(process.execPath, [`apps/${app}/index.mjs`], {
    cwd: sandbox.dir, env: { ...sandbox.env, ...extraEnv, PORT: String(port) },
  });
  let salida = '';
  proc.stdout.on('data', (c) => { salida += c; });
  proc.stderr.on('data', (c) => { salida += c; });

  const base = `http://127.0.0.1:${port}`;
  const muerto = new Promise((resolve) => proc.on('exit', (code) => resolve(code)));
  for (let i = 0; i < 100; i += 1) {
    if (proc.exitCode !== null) break;
    try {
      const r = await fetch(`${base}/health`);
      if (r.ok) {
        return { base, proc, salida: () => salida, parar: async () => { proc.kill(); await muerto; } };
      }
    } catch { /* todavia no escucha */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  proc.kill();
  throw new Error(`${app} no arranco en 10 s:\n${salida}`);
}

/** Arranca esperando que NO arranque: devuelve codigo de salida y salida. */
export async function arrancarYFallar(sandbox, app, extraEnv = {}) {
  const proc = spawn(process.execPath, [`apps/${app}/index.mjs`], {
    cwd: sandbox.dir, env: { ...sandbox.env, ...extraEnv, PORT: '0' },
  });
  let salida = '';
  proc.stdout.on('data', (c) => { salida += c; });
  proc.stderr.on('data', (c) => { salida += c; });
  const code = await new Promise((resolve) => {
    proc.on('exit', resolve);
    setTimeout(() => { proc.kill(); resolve(null); }, 10000);
  });
  return { code, salida };
}
