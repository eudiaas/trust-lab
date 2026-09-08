// El publisher, de punta a punta: sirve lo emitido y nada mas.
//
// Es el unico proceso que da la cara a internet, asi que sus propiedades no son
// de comodidad, son de seguridad, y ninguna se ve leyendo el codigo de una
// funcion suelta:
//
//   · arranca SIN TRUST_LAB_KEY —no puede descifrar ninguna clave privada ni
//     aunque quisiera— y aun asi publica,
//   · no tiene una sola ruta que escriba: cualquier metodo que no sea GET/HEAD
//     es 405, y pasar por el no siembra ni crea nada,
//   · sirve en la ruta que el documento DECLARA, porque esa URL viaja dentro de
//     lo firmado y servir en otra dejaria lo firmado apuntando a un 404,
//   · una version historica es inmutable: reemitir no cambia lo que devuelve.
//
// Corre contra SQL (PGlite) porque es lo que hay en produccion y porque el
// historial de artefactos solo existe ahi: en el almacen de fichero la version
// vieja la guarda git, no el proceso.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { contador, crearSandbox, cli, arrancar } from './harness.mjs';

const { check, fin } = contador();
const caja = crearSandbox({ pglite: true });
// El publisher no necesita la clave y no debe pedirla: se la quitamos del
// entorno para que el test lo demuestre en vez de suponerlo.
const sinClave = { ...caja.env };
delete sinClave.TRUST_LAB_KEY;

const RUTA_PROPIA = '/custom/mi-lista.json';
const cuerpo = (r) => r.text();
const conCuerpo = async (base, ruta, init) => {
  const r = await fetch(base + ruta, init);
  return { r, texto: await r.text() };
};

console.log('PUBLISHER: sirve lo emitido, y nada mas\n');

let pub;
try {
  // --- 1. Almacen vacio: no sirve nada y no crea nada ---------------------
  console.log('-- almacen vacio');
  pub = await arrancar({ ...caja, env: sinClave }, 'publisher');
  check('arranca sin TRUST_LAB_KEY', true);
  check('dice que es de solo lectura', pub.salida().includes('solo lectura'), pub.salida());
  const vacio = await (await fetch(pub.base + '/')).json();
  check('sin nada emitido, el indice sale vacio', vacio.published.length === 0);
  check('el indice se declara de solo lectura', vacio.readOnly === true);
  await pub.parar();

  // Que el indice saliera vacio no prueba que no escribiera: lo prueba que la
  // consola, al arrancar despues, todavia tenga que sembrar.
  console.log('\n-- siembra (solo la consola siembra)');
  // Antes de sembrar, una lista declara una ruta que no se parece a la
  // canonica: es la unica forma de comprobar que la tabla de rutas sale del
  // documento y no de una constante del servidor.
  const wrprcLab = JSON.parse(readFileSync(join(caja.dir, 'state/wrprc-lab.json'), 'utf8'));
  wrprcLab.url = 'https://trust-lab.espuni.com' + RUTA_PROPIA;
  writeFileSync(join(caja.dir, 'state/wrprc-lab.json'), JSON.stringify(wrprcLab, null, 2) + '\n');

  const consola = await arrancar(caja, 'console', { CONSOLE_PASSWORD: 'x' });
  check('la consola siembra lo que el publisher no habia tocado',
    /siembra inicial: \d+ documento/.test(consola.salida()), consola.salida());
  await consola.parar();

  // --- 2. Se emite material con el CLI -----------------------------------
  console.log('\n-- se emite algo que publicar');
  const pasos = [
    ['mint-tl-signer', 'tlso', 'av-lab'],
    ['mint-ca', 'iaca', 'C=ES, O=espuni S.L., CN=IACA AV'],
    ['mint-signer', 'iaca', 'av-ds', 'mdoc-ds', 'C=ES, O=espuni S.L., CN=AV DS'],
    ['add-provider', 'av-lab', 'av-ds', 'espuni S.L.', 'ES'],
    ['build-list', 'av-lab', 'tlso'],
    ['mint-signer', '-', 'wrprc-signer', 'wrprc', 'C=ES, O=espuni S.L., CN=WRPRC Signer'],
    ['add-entity', 'wrprc-lab', 'wrprc-signer', 'espuni S.L.'],
    ['build-lote', 'wrprc-lab', 'tlso'],
    ['new-status-list', 'status-lab', 'wrprc-signer', 'https://trust-lab.espuni.com/status/lab', '64'],
    ['status-build', 'status-lab'],
  ];
  const fallidos = pasos.map((p) => cli(caja, ...p)).filter((r) => r.code !== 0);
  check('el CLI deja tres artefactos emitidos', fallidos.length === 0,
    fallidos.map((f) => f.args.join(' ') + '\n' + f.err).join('\n'));
  const secuenciaAv = Number(cli(caja, 'graph').out.match(/av-lab\s+#(\d+)/)?.[1]);
  const xmlEmitido = cli(caja, 'export', 'lists', 'av-lab').out;

  // --- 3. Lo publicado ----------------------------------------------------
  console.log('\n-- lo publicado');
  pub = await arrancar({ ...caja, env: sinClave }, 'publisher');
  const indice = await (await fetch(pub.base + '/')).json();
  const av = indice.published.find((p) => p.id === 'av-lab');
  check('el indice lista la AV TL con su secuencia', av?.published?.sequence === secuenciaAv);
  check('el indice separa ruta declarada y canonica',
    indice.published.find((p) => p.id === 'wrprc-lab')?.path === RUTA_PROPIA);

  const declarada = await conCuerpo(pub.base, RUTA_PROPIA);
  check('sirve en la ruta que el documento declara', declarada.r.status === 200,
    `${declarada.r.status} en ${RUTA_PROPIA}`);
  check('la ruta declarada da el mismo artefacto que la canonica',
    declarada.texto === (await conCuerpo(pub.base, '/lote/wrprc-lab')).texto);

  const xml = await conCuerpo(pub.base, '/lists/av-lab.xml');
  check('la AV TL se sirve intacta', xml.texto.trim() === xmlEmitido.trim());
  check('Content-Type de la AV TL',
    xml.r.headers.get('content-type') === 'application/vnd.etsi.tsl+xml',
    xml.r.headers.get('content-type'));
  check('Content-Type del LoTE', declarada.r.headers.get('content-type') === 'application/jwt');
  check('Content-Type de la status list',
    (await fetch(pub.base + '/status/status-lab')).headers.get('content-type') === 'application/statuslist+jwt');
  check('nosniff en todas', xml.r.headers.get('x-content-type-options') === 'nosniff');
  check('CORS abierto: una wallet la lee desde cualquier origen',
    xml.r.headers.get('access-control-allow-origin') === '*');
  check('anuncia el NextUpdate', /^\d{4}-\d{2}-\d{2}T/.test(xml.r.headers.get('x-next-update') ?? ''));

  // --- 4. Cache ----------------------------------------------------------
  console.log('\n-- cache');
  const etag = xml.r.headers.get('etag');
  check('lleva ETag', !!etag);
  const revalidado = await fetch(pub.base + '/lists/av-lab.xml', { headers: { 'If-None-Match': etag } });
  check('revalidar con el mismo ETag da 304', revalidado.status === 304);
  const maxAge = Number(/max-age=(\d+)/.exec(xml.r.headers.get('cache-control'))?.[1]);
  check('la ultima version se cachea acotada', maxAge >= 60 && maxAge <= 3600, `max-age=${maxAge}`);
  check('la ultima version NO es immutable: una revocacion no espera',
    !xml.r.headers.get('cache-control').includes('immutable'));
  const historica = await fetch(`${pub.base}/lists/av-lab/${secuenciaAv}.xml`);
  check('una version concreta si es immutable',
    historica.headers.get('cache-control')?.includes('immutable'),
    historica.headers.get('cache-control'));

  // --- 5. Solo lectura ---------------------------------------------------
  console.log('\n-- solo lectura');
  for (const metodo of ['POST', 'PUT', 'DELETE', 'PATCH']) {
    const r = await fetch(pub.base + '/lists/av-lab.xml', { method: metodo });
    check(`${metodo} → 405, no 404`, r.status === 405 && r.headers.get('allow') === 'GET, HEAD',
      `${r.status} · Allow: ${r.headers.get('allow')}`);
  }
  const cabeza = await fetch(pub.base + '/lists/av-lab.xml', { method: 'HEAD' });
  check('HEAD responde como GET sin cuerpo', cabeza.status === 200 && (await cabeza.text()) === '');
  for (const ruta of ['/keys', '/keys/tlso', '/download/key/tlso', '/rps', '/graph']) {
    check(`${ruta} no existe aqui`, (await fetch(pub.base + ruta)).status === 404);
  }

  // Lo importante no es que esas rutas den 404, sino que NINGUNA de las que si
  // responden lleve material privado dentro.
  const rutas = ['/', ...indice.published.map((p) => p.path), ...indice.published.map((p) => p.canonical)];
  const filtrados = [];
  for (const ruta of rutas) {
    const t = await cuerpo(await fetch(pub.base + ruta));
    if (t.includes('PRIVATE KEY') || /"d"\s*:/.test(t) || t.includes('keyEnc')) filtrados.push(ruta);
  }
  check('ninguna ruta publicada filtra material privado', filtrados.length === 0, filtrados.join(', '));

  // --- 6. Inmutabilidad del historial ------------------------------------
  console.log('\n-- historial');
  const antes = xml.texto;
  await pub.parar();
  check('reemitir la lista', cli(caja, 'build-list', 'av-lab', 'tlso').code === 0);
  pub = await arrancar({ ...caja, env: sinClave }, 'publisher');
  const ahora = await conCuerpo(pub.base, '/lists/av-lab.xml');
  check('la raiz sirve la nueva version', ahora.texto !== antes);
  const vieja = await conCuerpo(pub.base, `/lists/av-lab/${secuenciaAv}.xml`);
  check('la version vieja sigue devolviendo sus bytes de siempre', vieja.texto.trim() === antes.trim(),
    'un artefacto firmado no se puede reconstruir: si no se guardo entero, se perdio');
  check('una version que no existe da 404',
    (await fetch(`${pub.base}/lists/av-lab/9999.xml`)).status === 404);
  check('un documento que no existe da 404', (await fetch(pub.base + '/lists/no-existe')).status === 404);
} finally {
  await pub?.parar().catch(() => {});
  caja.limpiar();
}

fin();
