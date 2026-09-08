// La consola, de punta a punta: la superficie de escritura, por HTTP.
//
// `views.mjs` ya comprueba que cada pantalla se pinta; esto comprueba lo otro,
// que es donde estan los fallos caros:
//
//   · no arranca sin contrasena, y sin sesion NADA responde —tampoco la
//     descarga de claves, que es la ruta que de verdad importa,
//   · una cookie manipulada o caducada no vale: la firma se comprueba,
//   · un error de operacion vuelve como aviso en pantalla, no como 500 ni como
//     pila,
//   · el flujo entero de emision funciona pulsando botones, no solo desde el
//     CLI: hay operaciones que SOLO existen aqui (asignar emisor a una status
//     list, editar los miembros de una lista, el reset).
//
// Corre contra SQL (PGlite), que es lo que hay en produccion. No es un detalle:
// el fallo de "no existe" al guardar los miembros de una lista solo se
// reproducia ahi, porque en fichero el documento lleva su `id` dentro y en
// Postgres la clave primaria es `(kind, id)`.
import { contador, crearSandbox, arrancar, arrancarYFallar } from './harness.mjs';

const { check, fin } = contador();
const caja = crearSandbox({ pglite: true });
const CLAVE = 'contrasena-de-laboratorio';

let cookie = null;
let base = '';

const get = (ruta, opts = {}) =>
  fetch(base + ruta, { redirect: 'manual', headers: { ...(cookie ? { cookie } : {}), ...(opts.headers ?? {}) } });

/** POST de formulario, como lo manda el navegador. Devuelve el aviso resultante. */
async function post(ruta, campos) {
  const cuerpo = new URLSearchParams();
  for (const [k, v] of Object.entries(campos)) {
    for (const uno of Array.isArray(v) ? v : [v]) cuerpo.append(k, uno);
  }
  const r = await fetch(base + ruta, {
    method: 'POST', redirect: 'manual', body: cuerpo,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(cookie ? { cookie } : {}) },
  });
  const destino = r.headers.get('location') ?? '';
  const params = new URLSearchParams(destino.split('?')[1] ?? '');
  return { status: r.status, destino, ok: params.get('ok'), bad: params.get('bad') };
}

/** El editor pinta el documento escapado dentro del textarea. */
const desescapar = (s) => s
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
  .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
const docDelEditor = async (id) => {
  const html = await (await get(`/docs/${id}`)).text();
  return JSON.parse(desescapar(/<textarea[^>]*>([\s\S]*?)<\/textarea>/.exec(html)[1]));
};

const seOperoBien = async (nombre, ruta, campos, contiene) => {
  const r = await post(ruta, campos);
  check(nombre, r.status === 303 && !!r.ok && (!contiene || r.ok.includes(contiene)),
    `${r.status} · ok=${r.ok} · bad=${r.bad}`);
  return r;
};

const seNego = async (nombre, ruta, campos, contiene) => {
  const r = await post(ruta, campos);
  check(nombre, r.status === 303 && !!r.bad && (!contiene || r.bad.includes(contiene)),
    `${r.status} · ok=${r.ok} · bad=${r.bad}`);
  return r;
};

console.log('CONSOLA: la superficie de escritura, por HTTP\n');

let consola;
try {
  // --- 1. Fail-closed -----------------------------------------------------
  console.log('-- arranque');
  const sinClave = await arrancarYFallar(caja, 'console');
  check('sin CONSOLE_PASSWORD no arranca', sinClave.code === 1, `exit=${sinClave.code}`);
  check('y dice por que', sinClave.salida.includes('no se arranca sin autenticacion'), sinClave.salida);

  consola = await arrancar(caja, 'console', { CONSOLE_PASSWORD: CLAVE });
  base = consola.base;
  check('siembra al arrancar contra un almacen vacio',
    /siembra inicial: \d+ documento/.test(consola.salida()), consola.salida());

  // --- 2. Sin sesion no responde nada -------------------------------------
  console.log('\n-- sin sesion');
  const cerradas = ['/', '/keys', '/lists', '/rps', '/wrprc', '/graph', '/graph.svg', '/reset',
    '/docs/av-lab', '/lists/av-lab', '/download/key/tlso', '/download/lists/av-lab'];
  const abiertas = [];
  for (const ruta of cerradas) if ((await get(ruta)).status !== 401) abiertas.push(ruta);
  check('toda ruta pide sesion, la descarga de claves incluida', abiertas.length === 0, abiertas.join(', '));
  check('/health responde sin sesion: es para el orquestador', (await get('/health')).status === 200);
  const escrituraAnonima = await post('/keys/ca', { name: 'colada', subject: 'C=ES, O=X, CN=X' });
  check('una escritura sin sesion no pasa', escrituraAnonima.status === 401);

  const mala = await post('/login', { password: 'otra cosa' });
  check('contrasena incorrecta: 401 y sin cookie', mala.status === 401);

  const buena = await fetch(base + '/login', {
    method: 'POST', redirect: 'manual', body: new URLSearchParams({ password: CLAVE }),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  const setCookie = buena.headers.get('set-cookie') ?? '';
  check('contrasena correcta: 303 y cookie de sesion', buena.status === 303 && setCookie.startsWith('tl='));
  check('la cookie es HttpOnly y SameSite=Strict',
    setCookie.includes('HttpOnly') && setCookie.includes('SameSite=Strict'), setCookie);
  cookie = setCookie.split(';')[0];

  const [exp, mac] = cookie.slice(3).split('.');
  const manipulada = cookie;
  cookie = `tl=${exp}.${mac.slice(0, -2)}xx`;
  check('una cookie con la firma tocada no vale', (await get('/keys')).status === 401);
  cookie = `tl=${Date.now() - 1000}.${mac}`;
  check('una cookie caducada no vale', (await get('/keys')).status === 401);
  cookie = manipulada;
  check('con la cookie buena si', (await get('/keys')).status === 200);

  // --- 3. Lectura ---------------------------------------------------------
  console.log('\n-- lectura');
  for (const ruta of ['/', '/keys', '/lists', '/rps', '/wrprc', '/graph', '/reset', '/docs/av-lab', '/lists/av-lab']) {
    const r = await get(ruta);
    check(`GET ${ruta}`, r.status === 200, `${r.status}`);
  }
  const portada = await get('/');
  check('la portada es informativa: sin formularios de emision',
    !(await portada.text()).includes('<form method="post" action="/keys/ca"'));
  check('noindex en las paginas', portada.headers.get('x-robots-tag') === 'noindex');
  const svg = await get('/graph.svg');
  check('/graph.svg se descarga como SVG',
    svg.headers.get('content-type') === 'image/svg+xml' &&
    (svg.headers.get('content-disposition') ?? '').includes('attachment'));
  check('/status redirige a /wrprc', (await get('/status')).headers.get('location') === '/wrprc');
  check('una status list no tiene pagina de miembros',
    (await get('/lists/status-wrprc')).headers.get('location') === '/status');
  check('un documento que no existe da 404', (await get('/docs/no-existe')).status === 404);

  // --- 4. El flujo entero, pulsando botones -------------------------------
  console.log('\n-- emision');
  await seOperoBien('firmante de listas', '/keys/tlso', { name: 'tlso', scheme: 'av-lab' }, 'tlso');
  await seOperoBien('CA', '/keys/ca', { name: 'iaca', subject: 'C=ES, O=espuni S.L., CN=IACA AV' });
  await seOperoBien('Document Signer bajo la CA', '/keys/signer',
    { name: 'av-ds', issuer: 'iaca', role: 'mdoc-ds', subject: 'C=ES, O=espuni S.L., CN=AV DS' }, 'av-ds');
  await seNego('un DS de mdoc autofirmado se niega, con motivo', '/keys/signer',
    { name: 'suelto', issuer: '', role: 'mdoc-ds', subject: 'C=ES, O=X, CN=Y' }, 'IACA');

  // El editor de miembros: la operacion que solo existe aqui, y la que fallaba
  // con "no existe" en cuanto el almacen era Postgres.
  await seOperoBien('miembros de la AV TL', '/lists/av-lab/providers',
    { sel: 'key:av-ds', 'name:av-ds': 'espuni S.L.', 'cc:av-ds': 'ES' }, '1 entrada');
  const docAv = await (await get('/docs/av-lab')).text();
  check('el alta queda guardada en el documento', docAv.includes('espuni S.L.'));
  await seOperoBien('emitir la AV TL', '/lists/av-lab/build', { signer: 'tlso' }, 'emitida');
  await seNego('emitir con un firmante que no cumple 5.7.1', '/lists/av-lab/build', { signer: 'iaca' }, 'TLSO');

  await seOperoBien('firmante de WRPRC autofirmado', '/keys/signer',
    { name: 'wrprc-signer', issuer: '', role: 'wrprc', subject: 'C=ES, O=espuni S.L., CN=WRPRC Signer' },
    'autofirmado');
  await seOperoBien('miembros de la lista de WRPRC', '/lists/wrprc-lab/providers',
    { sel: 'key:wrprc-signer', 'name:wrprc-signer': 'espuni S.L.', 'cc:wrprc-signer': 'ES' });
  await seOperoBien('emitir la lista LoTE', '/lists/wrprc-lab/build', { signer: 'tlso' }, 'emitida');

  await seOperoBien('crear status list', '/wrprc',
    { id: 'status-lab', issuerKey: 'wrprc-signer', url: 'https://trust-lab.espuni.com/status/lab', size: '64' },
    'wrprc-signer');
  // Asignar emisor a una lista que no lo tenia: no hay comando de CLI para esto.
  await seOperoBien('asignar emisor a la status list sembrada', '/wrprc/status-wrprc/issuer',
    { issuerKey: 'wrprc-signer' }, 'revoca');

  await seOperoBien('alta de relying party', '/rps',
    { id: 'lab-rp', legalName: 'Lab S.L.', country: 'es', identifierValue: 'B99999999',
      identifierType: 'http://data.europa.eu/eudi/id/VATIN', statusList: 'status-lab' }, 'esqueleto valido');
  check('la ficha del RP se abre', (await get('/rps/lab-rp')).status === 200);
  // La IACA no esta publicada en la lista de prestadores de access
  // certificates, asi que lo que salga no encadena con nada. Se emite igual
  // —en un laboratorio se montan escenarios rotos a proposito— pero el aviso
  // tiene que llegar a la pantalla, no quedarse en el objeto de retorno.
  const acceso = await seOperoBien('access certificate', '/rps/lab-rp/wrpac',
    { service: 'svc-1', ca: 'iaca' }, 'NCP-l-eudiwrp');
  check('el access certificate avisa de que su CA no esta publicada',
    /no esta publicada/.test(acceso.ok ?? ''), acceso.ok ?? '');
  await seOperoBien('registration certificate', '/rps/lab-rp/wrprc',
    { service: 'svc-1', use: 'use-1', signer: 'wrprc-signer' }, 'WRPRC lab-rp-svc-1-use-1');

  await seOperoBien('marcar una posicion como revocada', '/wrprc/status-lab/set',
    { idx: '3', status: 'invalid', note: 'prueba' }, 'Pendiente de reemitir');
  await seOperoBien('emitir la status list', '/wrprc/status-lab/build', {}, '1 no valida');

  // --- 5. Descargas -------------------------------------------------------
  console.log('\n-- descargas');
  const cadena = await get('/download/key/wrprc-signer?form=chain');
  const cadenaTexto = await cadena.text();
  check('la cadena se descarga', cadena.status === 200 && cadenaTexto.includes('BEGIN CERTIFICATE'));
  check('con nombre de fichero y sin cache',
    (cadena.headers.get('content-disposition') ?? '').includes('filename=') &&
    cadena.headers.get('cache-control') === 'no-store');
  const privada = await get('/download/key/wrprc-signer?form=bundle');
  check('la privada solo sale por aqui, y con sesion',
    (await privada.text()).includes('BEGIN PRIVATE KEY'));
  check('la descarga de la privada queda en el log',
    consola.salida().includes('[export] clave privada'), consola.salida().slice(-400));
  const artefacto = await get('/download/lists/av-lab');
  check('el artefacto emitido se descarga', (await artefacto.text()).includes('TrustServiceStatusList'));
  check('una clave que no existe da 404', (await get('/download/key/ninguna')).status === 404);

  // --- 6. Borrado y reset -------------------------------------------------
  console.log('\n-- borrado');
  await seNego('borrar una clave de la que cuelgan cosas', '/delete/key/wrprc-signer', {}, 'dependen de el');
  check('la clave sigue ahi', (await get('/download/key/wrprc-signer?form=chain')).status === 200);
  await seOperoBien('borrar el WRPRC', '/delete/wrprc/lab-rp-svc-1-use-1', { rp: 'lab-rp' }, 'Borrado');
  await seOperoBien('borrar el RP', '/delete/rp/lab-rp', {}, 'Borrado');
  await seOperoBien('retirar una lista publicada', '/delete/unpublish/wrprc-lab', {}, 'deja de servirse');

  // Un JSON que no cumple el modelo no se guarda: el editor valida.
  await seNego('el editor no guarda un registro que no valida', '/docs/espuni-rp',
    { doc: JSON.stringify({ walletRelyingParty: { legalName: 'X' } }) }, 'TS5');
  // Guardar y releer, con el `kind` cambiado por el camino: en SQL la clave
  // primaria es `(kind, id)`, asi que un `put` sin borrar antes dejaria la fila
  // vieja ahi y `get('*', id)` podria devolver esa — el documento editado
  // reapareceria como estaba.
  const antesDeEditar = await docDelEditor('av-lab');
  await seOperoBien('el editor guarda', '/docs/av-lab',
    { doc: JSON.stringify({ ...antesDeEditar, kind: 'lote-json', loteType: 'EUWRPRCProvidersList',
      _marca: 'editado-en-el-test' }) }, 'Guardado');
  const editado = await docDelEditor('av-lab');
  check('cambiar el kind no deja una fila fantasma detras',
    editado._marca === 'editado-en-el-test' && editado.kind === 'lote-json',
    JSON.stringify({ kind: editado.kind, marca: editado._marca }));
  await seOperoBien('el editor lo devuelve a su sitio', '/docs/av-lab',
    { doc: JSON.stringify(antesDeEditar) }, 'Guardado');
  check('y vuelve a ser la lista XML', (await docDelEditor('av-lab')).kind === 'etsi-tl-xml');

  await seNego('el reset pide confirmacion literal', '/reset', { scope: 'publicado', confirm: 'si' });
  await seOperoBien('el reset retira lo publicado', '/reset',
    { scope: 'publicado', confirm: 'RETIRAR' }, 'Retirados');
  check('tras el reset las claves siguen ahi',
    (await get('/download/key/wrprc-signer?form=chain')).status === 200);
} finally {
  await consola?.parar().catch(() => {});
  caja.limpiar();
}

fin();
