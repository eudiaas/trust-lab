// El CLI, de punta a punta: se monta un marco de confianza entero y se
// comprueba lo que sale.
//
// Existe porque el CLI es la unica superficie sin red debajo. Las vistas tienen
// su humo, los formatos firmados su suite de firmas y el almacen su
// conformidad; el CLI se ejercitaba a mano, que es otra forma de decir que se
// ejercitaba cuando alguien se acordaba. Y es la superficie donde mas barato
// sale romper algo sin enterarse: no tiene build, no tiene tipos, y sus
// comandos se llaman entre paquetes por nombre.
//
// Lo que comprueba no es que imprima lo que imprime, sino las propiedades que
// cuestan un despliegue si se rompen:
//
//   · que la lista publique el certificado que le toca (la AV TL el DS, no la
//     IACA; el anexo F la CA emisora, no la hoja),
//   · que el WRPRC emitido apunte a la posicion que el CLI dijo,
//   · que reemitir mueva la posicion y no recicle la vieja (13.2 y 13.3),
//   · que un cambio de estado no se publique hasta reemitir la lista,
//   · que un incumplimiento de perfil salga como mensaje y no como pila.
//
// Se ejecuta contra una raiz temporal —copia de apps/, packages/ y state/, con
// node_modules enlazado— asi que no toca ni el repo ni ninguna base de datos.
// El entorno se limpia a proposito de DATABASE_URL y TRUST_LAB_PGLITE: un test
// que escribiera en el Postgres del operador seria peor que no tenerlo.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, cpSync, symlinkSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { randomBytes } from 'node:crypto';

const ROOT = join(dirname(new URL(import.meta.url).pathname), '..');
const SANDBOX = mkdtempSync(join(tmpdir(), 'trustlab-e2e-'));
for (const dir of ['apps', 'packages', 'state']) {
  cpSync(join(ROOT, dir), join(SANDBOX, dir), { recursive: true });
}
symlinkSync(join(ROOT, 'node_modules'), join(SANDBOX, 'node_modules'));

const ENV = { ...process.env, TRUST_LAB_KEY: randomBytes(32).toString('hex') };
delete ENV.DATABASE_URL;
delete ENV.TRUST_LAB_PGLITE;
delete ENV.RAILWAY_ENVIRONMENT_NAME;
delete ENV.RAILWAY_ENVIRONMENT;

let fallos = 0;
const check = (nombre, cond, detalle = '') => {
  if (cond) console.log(`  ok   ${nombre}`);
  else { fallos += 1; console.log(`  FALLO ${nombre}${detalle ? '\n       ' + detalle : ''}`); }
};

/** Ejecuta el CLI como lo ejecutaria un operador: proceso aparte, argv y salida. */
function cli(...args) {
  const r = spawnSync(process.execPath, ['apps/cli/index.mjs', ...args], {
    cwd: SANDBOX, env: ENV, encoding: 'utf8',
  });
  return { code: r.status, out: r.stdout ?? '', err: r.stderr ?? '', args };
}

/** Comando que tiene que salir bien. Si no, se ve la salida entera. */
function ok(nombre, ...args) {
  const r = cli(...args);
  check(nombre, r.code === 0, r.code === 0 ? '' : `exit=${r.code}\n       ${(r.err || r.out).trim().split('\n').join('\n       ')}`);
  return r;
}

/**
 * Comando que tiene que fallar CON MENSAJE. Las dos mitades cuentan: un
 * incumplimiento de perfil es un resultado del programa, no una excepcion sin
 * atrapar, asi que una pila en stderr es un fallo aunque el codigo de salida
 * sea el correcto.
 */
function falla(nombre, esperado, ...args) {
  const r = cli(...args);
  const pila = /^\s+at /m.test(r.err);
  check(nombre,
    r.code === 1 && r.err.includes(esperado) && !pila,
    `exit=${r.code}${pila ? ' · vuelca la pila' : ''}\n       ${r.err.trim().split('\n').join('\n       ')}`);
  return r;
}

const leer = (rel) => readFileSync(join(SANDBOX, rel), 'utf8');
const doc = (id) => JSON.parse(leer(`state/${id}.json`));
const sinEspacios = (s) => s.replace(/\s+/g, '');
const cuerpoPem = (pem) => sinEspacios(pem.replace(/-----[^-]+-----/g, ''));
const certsDe = (pem) => (pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []);
const b64url = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
// Una lista LoTE se publica como JWS compacto: lo que contiene esta en el
// payload, no en el fichero en claro.
const cargaLote = (rel) => sinEspacios(Buffer.from(leer(rel).trim().split('.')[1], 'base64url').toString('utf8'));
const certDe = (nombre, n = 0) => cuerpoPem(certsDe(cli('export-key', nombre, 'chain').out)[n]);

console.log('CLI: se monta el marco entero y se comprueba lo que sale\n');

try {
  // --- 1. Listas ---------------------------------------------------------
  console.log('-- listas');
  ok('mint-tl-signer: firmante con el perfil 5.7.1', 'mint-tl-signer', 'tlso', 'av-lab');
  ok('mint-ca: IACA', 'mint-ca', 'iaca', 'C=ES, O=espuni S.L., CN=IACA AV');
  ok('mint-leaf: hoja de esa CA', 'mint-leaf', 'iaca', 'hoja', 'C=ES, O=espuni S.L., CN=Hoja');
  ok('mint-signer: DS de mdoc bajo la IACA', 'mint-signer', 'iaca', 'av-ds', 'mdoc-ds', 'C=ES, O=espuni S.L., CN=AV DS');
  ok('add-provider: alta en la AV TL', 'add-provider', 'av-lab', 'av-ds', 'espuni S.L.', 'ES');

  const av = ok('build-list: AV Trusted List firmada', 'build-list', 'av-lab', 'tlso');
  check('build-list: se verifica antes de guardarse', av.out.includes('verificada con @owf/eudi-tl'));
  check('build-list: el XML queda escrito', existsSync(join(SANDBOX, 'out/lists/av-lab.xml')));

  // La propiedad de fondo de `identityCertOf`: cada perfil publica un
  // certificado distinto del mismo par, y publicar el otro no encadena.
  const xml = sinEspacios(leer('out/lists/av-lab.xml'));
  const cadenaDs = certsDe(ok('export-key: cadena del DS', 'export-key', 'av-ds', 'chain').out);
  check('AV TL: publica el DS', xml.includes(cuerpoPem(cadenaDs[0])));
  check('AV TL: NO publica la IACA', !xml.includes(cuerpoPem(cadenaDs[1])),
    'la AV TL publica el Document Signer, no el ancla que lo emitio');

  const auto = ok('mint-signer: firmante de WRPRC autofirmado', 'mint-signer', '-', 'wrprc-signer', 'wrprc',
    'C=ES, O=espuni S.L., CN=WRPRC Signer');
  check('mint-signer: dice que sale autofirmado', auto.out.includes('autofirmado'));

  ok('add-entity: alta en la lista de WRPRC', 'add-entity', 'wrprc-lab', 'wrprc-signer', 'espuni S.L.');
  const lote = ok('build-lote: lista LoTE firmada', 'build-lote', 'wrprc-lab', 'tlso');
  check('build-lote: el JWS se relee', lote.out.includes('JWS verificado'));

  check('EUWRPRCProvidersList: publica el certificado del firmante',
    cargaLote('out/lote/wrprc-lab.json').includes(certDe('wrprc-signer')));

  // El anexo F publica la CA emisora, no la hoja. Para que la diferencia se
  // note hace falta un par de dos certificados: con un autofirmado, hoja y
  // ancla son el mismo y el perfil no se estaria comprobando.
  ok('mint-ca: CA de access certificates', 'mint-ca', 'access-ca', 'C=ES, O=espuni S.L., CN=Access CA');
  ok('mint-leaf: hoja bajo esa CA', 'mint-leaf', 'access-ca', 'access-hoja', 'C=ES, O=espuni S.L., CN=Access Leaf');
  ok('add-entity: alta en la lista de WRPAC', 'add-entity', 'wrpac-lab', 'access-hoja', 'espuni S.L.');
  ok('build-lote: lista de WRPAC', 'build-lote', 'wrpac-lab', 'tlso');
  const wrpacLista = cargaLote('out/lote/wrpac-lab.json');
  check('EUWRPACProvidersList: publica la CA emisora (anexo F)', wrpacLista.includes(certDe('access-hoja', 1)));
  check('EUWRPACProvidersList: NO publica la hoja', !wrpacLista.includes(certDe('access-hoja', 0)));

  // --- 2. Relying party, access y registration certificates --------------
  console.log('\n-- relying party');
  ok('new-status-list: lista de revocacion del emisor', 'new-status-list', 'status-lab', 'wrprc-signer',
    'https://trust-lab.example/status/lab', '64');
  const rp = ok('new-rp: esqueleto valido', 'new-rp', 'lab-rp', 'Lab S.L.', 'B99999999', 'ES', 'status-lab');
  check('new-rp: la posicion no se reserva al dar de alta', !/posicion \d/.test(rp.out),
    'la 21 §1 dice "allocated an index during issuance"');

  const wrpac = ok('mint-wrpac: access certificate', 'mint-wrpac', 'access-ca', 'lab-rp', 'svc-1');
  check('mint-wrpac: el identificador semantico va en el subject', wrpac.out.includes('VATES-B99999999'));
  check('mint-wrpac: politica NCP-l-eudiwrp', wrpac.out.includes('0.4.0.194118.1.2'));

  const emision = ok('issue-wrprc: registration certificate', 'issue-wrprc', 'lab-rp', 'svc-1', 'use-1', 'wrprc-signer');
  const idx1 = Number(emision.out.match(/posicion (\d+)/)?.[1]);
  check('issue-wrprc: entrega una posicion', Number.isInteger(idx1));
  check('issue-wrprc: la relee para detectar la edicion', /edicion detectada al releerlo: v1\.\d/.test(emision.out));

  // El artefacto tiene que decir lo mismo que dijo el CLI: si el `idx` que
  // viaja firmado no es el que se reservo, la revocacion apunta a otro sitio.
  const jwt = leer('out/wrprc/lab-rp-svc-1-use-1.jwt').trim();
  const [h, p, firma] = jwt.split('.');
  const payload = b64url(p);
  check('WRPRC: la firma es base64url', /^[A-Za-z0-9_-]+$/.test(firma) && !/^\d+(,\d+)+$/.test(firma));
  check('WRPRC: ES256', b64url(h).alg === 'ES256');
  check('WRPRC: apunta a la posicion que el CLI dijo', payload.status?.status_list?.idx === idx1,
    `CLI ${idx1} · certificado ${payload.status?.status_list?.idx}`);
  check('WRPRC: apunta a la URL de la lista',
    payload.status?.status_list?.uri === 'https://trust-lab.example/status/lab');

  const reemision = ok('issue-wrprc: reemision', 'issue-wrprc', 'lab-rp', 'svc-1', 'use-1', 'wrprc-signer');
  const idx2 = Number(reemision.out.match(/posicion (\d+)/)?.[1]);
  check('reemision: posicion nueva (13.2)', idx2 !== idx1, `${idx1} → ${idx2}`);
  const posiciones = doc('status-lab').positions ?? doc('status-lab').entries ?? {};
  check('reemision: la vieja queda anotada como liberada',
    posiciones[idx1] !== undefined && posiciones[idx1].releasedAt !== undefined);

  // Que quede anotada no basta: lo que la 13.3 pide es que NO vuelva al
  // sorteo. Se ve emitiendo para otro titular, que es cuando reciclar hace
  // dano — el nuevo heredaria el rastro del viejo y el veredicto guardado
  // sobre uno se aplicaria al otro.
  ok('new-rp: segundo titular en la misma lista', 'new-rp', 'otro-rp', 'Otro Lab S.L.', 'B77777777', 'ES', 'status-lab');
  const tercera = ok('issue-wrprc: para el segundo titular', 'issue-wrprc', 'otro-rp', 'svc-1', 'use-1', 'wrprc-signer');
  const idx3 = Number(tercera.out.match(/posicion (\d+)/)?.[1]);
  check('otro titular: no hereda ninguna posicion gastada (13.3)',
    idx3 !== idx1 && idx3 !== idx2, `${idx1}, ${idx2} → ${idx3}`);

  // Con la lista grande el sorteo esconde el reciclaje: aunque una posicion
  // liberada volviera al bombo, es improbable que salga justo esa. Con dos
  // posiciones no hay donde esconderse — gastadas las dos, la emision tiene
  // que fallar. Si en vez de fallar entrega una liberada, se ve aqui.
  ok('new-status-list: lista de dos posiciones', 'new-status-list', 'status-mini', 'wrprc-signer',
    'https://trust-lab.example/status/mini', '2');
  ok('new-rp: titular de la lista minima', 'new-rp', 'mini-rp', 'Mini S.L.', 'B55555555', 'ES', 'status-mini');
  ok('issue-wrprc: gasta la primera', 'issue-wrprc', 'mini-rp', 'svc-1', 'use-1', 'wrprc-signer');
  ok('issue-wrprc: gasta la segunda', 'issue-wrprc', 'mini-rp', 'svc-1', 'use-1', 'wrprc-signer');
  falla('lista agotada: se niega antes que reciclar (13.3)', 'no tiene posiciones libres',
    'issue-wrprc', 'mini-rp', 'svc-1', 'use-1', 'wrprc-signer');

  // --- 3. Revocacion -----------------------------------------------------
  console.log('\n-- revocacion');
  ok('status-build: la lista de estados', 'status-build', 'status-lab');
  check('status-check: la posicion viva sale valida',
    cli('status-check', 'status-lab', String(idx2), 'wrprc-signer').out.includes('→ valid'));

  ok('status-set: marcar invalida', 'status-set', 'status-lab', String(idx2), 'invalid', 'prueba e2e');
  check('status-set: NO publica hasta reemitir',
    cli('status-check', 'status-lab', String(idx2), 'wrprc-signer').out.includes('→ valid'),
    'lo publicado es el artefacto firmado, no el estado en el documento');

  const rebuild = ok('status-build: reemitir', 'status-build', 'status-lab');
  check('status-build: la firma su emisor', rebuild.out.includes('firmada por wrprc-signer'));
  check('status-check: ahora sale invalida',
    cli('status-check', 'status-lab', String(idx2), 'wrprc-signer').out.includes('→ invalid'));

  falla('status-build: el TLSO no puede firmarla', 'la firma su emisor',
    'status-build', 'status-lab', 'tlso');

  // --- 4. Exportacion ----------------------------------------------------
  console.log('\n-- exportacion');
  const cadena = cli('export-key', 'wrprc-signer', 'chain');
  check('export-key chain: no anuncia secreto', !cadena.err.includes('clave privada'));
  check('export-key chain: sale un PEM de certificado', cadena.out.includes('BEGIN CERTIFICATE'));
  const privada = cli('export-key', 'wrprc-signer', 'bundle');
  check('export-key bundle: avisa de que lleva la privada', privada.err.includes('clave privada'));
  check('export-key bundle: lleva la privada', privada.out.includes('BEGIN PRIVATE KEY'));
  const jwk = cli('export-key', 'wrprc-signer', 'jwk');
  check('export-key jwk: JSON con la curva', JSON.parse(jwk.out).crv === 'P-256');
  const salida = join(SANDBOX, 'export/');
  ok('export: el WRPRC emitido', 'export', 'wrprc', 'lab-rp-svc-1-use-1', salida);
  check('export: la AV TL emitida', cli('export', 'lists', 'av-lab').out.includes('TrustServiceStatusList'));

  // --- 5. Errores esperados ----------------------------------------------
  console.log('\n-- errores esperados');
  const nada = cli('frobnicate');
  check('comando desconocido: exit 1 y uso', nada.code === 1 && nada.err.startsWith('uso: trustlab'));
  falla('mdoc-ds autofirmado: se rechaza', 'cuelga de una IACA',
    'mint-signer', '-', 'suelto', 'mdoc-ds', 'C=ES, O=X, CN=Y');
  falla('rol desconocido: lista los que hay', 'rol desconocido',
    'mint-signer', 'iaca', 'x', 'rol-inventado', 'C=ES, O=X, CN=Y');
  falla('emisor que no es CA', 'no es una CA',
    'mint-signer', 'wrprc-signer', 'x', 'wrprc', 'C=ES, O=X, CN=Y');
  falla('add-provider sin pais', 'ISO 3166-1', 'add-provider', 'av-lab', 'av-ds', 'X');
  falla('new-rp con id repetido', 'ya existe', 'new-rp', 'lab-rp', 'Otra', 'B1', 'ES');
  falla('new-rp con id invalido', 'solo admite minusculas', 'new-rp', 'MAYUS', 'Otra', 'B1');
  falla('firmante que no existe', 'x-no-existe', 'build-lote', 'wrprc-lab', 'x-no-existe');
  falla('documento que no existe', 'no-existe', 'unpublish', 'no-existe');

  // --- 6. Grafo y borrado ------------------------------------------------
  console.log('\n-- grafo y borrado');
  const grafo = ok('graph: recorre lo publicado', 'graph');
  check('graph: la AV TL aparece publicada', /av-lab\s+#\d/.test(grafo.out));
  const mermaid = ok('graph mermaid', 'graph', 'mermaid');
  check('graph mermaid: sale un grafo', mermaid.out.startsWith('graph LR'));
  check('graph mermaid: el WRPRC cuelga de su firmante', mermaid.out.includes('firmado-por'));

  const negado = falla('delete-key: avisa de quien depende', 'dependen de el', 'delete-key', 'wrprc-signer');
  check('delete-key: nombra las dependencias, no dice "hay dependencias"',
    negado.err.includes('lab-rp-svc-1-use-1') && negado.err.includes('status-lab'));
  check('delete-key: la clave sigue ahi', cli('export-key', 'wrprc-signer', 'chain').code === 0);

  ok('delete-wrprc', 'delete-wrprc', 'lab-rp-svc-1-use-1');
  const borradoRp = ok('delete-rp', 'delete-rp', 'lab-rp');
  check('delete-rp: retira el access certificate', borradoRp.out.includes('lab-rp-svc-1-access'));
  check('delete-rp: la posicion queda liberada, no libre', borradoRp.out.includes('no se reasigna'));

  ok('delete-key con force', 'delete-key', 'wrprc-signer', 'force');
  check('delete-key force: la clave ya no esta', cli('export-key', 'wrprc-signer', 'chain').code === 1);

  const retirada = ok('unpublish', 'unpublish', 'av-lab');
  check('unpublish: dice que deja de servirse', retirada.out.includes('deja de servirse'));
  ok('remove-provider', 'remove-provider', 'av-lab', 'espuni S.L.');
  check('remove-provider: recuerda que no publica solo',
    cli('remove-provider', 'wrprc-lab', 'espuni S.L.').out.includes('reemitir la lista'));
} finally {
  rmSync(SANDBOX, { recursive: true, force: true });
}

console.log(fallos ? `\n${fallos} FALLO(S)` : '\nTODO OK');
process.exit(fallos ? 1 : 0);
