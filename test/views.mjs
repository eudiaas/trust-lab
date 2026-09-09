// Toda vista se renderiza sin explotar.
//
// Existe por un fallo tonto y caro: al reescribir el dashboard, el reemplazo se
// llevo por delante `ID_TYPE_LABELS`, que estaba entre esa funcion y la
// siguiente. Nada fallo al arrancar —las plantillas no se evaluan hasta que se
// pintan— y `/rps` daba "ID_TYPE_LABELS is not defined" solo al visitarla.
//
// La consola no tiene build ni framework, asi que este humo es lo unico que
// distingue "compila" de "funciona". Con datos minimos basta: lo que caza son
// referencias que no existen, no la maquetacion.
import * as views from '../apps/console/views.mjs';

const MINIMOS = {
  loginPage: {},
  dashboard: { estado: [], faltan: [], rps: [], svg: '' },
  keysPage: { keys: [], cas: [], roles: {}, schemes: [] },
  listsPage: { items: [] },
  listMembersPage: {
    id: 'x', item: null, doc: { kind: 'lote-json' }, esAv: false,
    candidatos: [], huerfanos: [], keys: [],
  },
  rpsPage: { rps: [], statusLists: [] },
  rpPage: { rp: { id: 'x', legalName: 'X', problems: [], services: [] }, signers: [], cas: [], statusLists: [] },
  wrprcPage: { emisores: [], huerfanas: [], candidatos: [] },
  graphPage: { svg: '', graph: { nodes: [], edges: [] }, dangling: [] },
  docPage: { id: 'x', doc: {}, problems: [], title: 'x', back: '/' },
  resetPage: { preview: { publicado: [], wrprc: [], keys: [], docs: [] } },
};

// Con datos: una vista vacia puede no recorrer las ramas que usan las variables.
const CON_DATOS = {
  rpsPage: {
    rps: [{ id: 'rp', legalName: 'RP', problems: [], services: [{ id: 's', name: 'S', uses: [] }] }],
    statusLists: [],
  },
  wrprcPage: {
    emisores: [{
      key: 'k', nombre: 'N', subject: 'CN=x',
      listas: [{
        id: 'l', url: 'https://x', size: 8, enUso: 1, revocadas: 1, published: { sequence: 1 },
        posiciones: [
          { idx: 1, status: 'invalid', note: 'n', releasedAt: null, motivo: null,
            cert: { rp: 'rp', legalName: 'RP', service: 's', use: 'u', publicado: true }, anotado: null },
          { idx: 2, status: 'valid', note: null, releasedAt: '2026-01-01', motivo: 'm',
            cert: null, anotado: 'rp / s / u' },
        ],
      }],
    }],
    huerfanas: [{ id: 'h', url: null, size: 8, enUso: 0, revocadas: 0, published: null, posiciones: [] }],
    candidatos: [{ name: 'k', subject: 'CN=x' }],
  },
  dashboard: {
    estado: [
      { pieza: 'Firmante de listas', donde: '/keys', ok: true, detalle: 'x' },
      { pieza: 'Lista', donde: '/lists/av-lab', ok: false, parcial: true, detalle: 'y' },
      { pieza: 'Otra', donde: '/rps', ok: false, detalle: 'z' },
    ],
    faltan: [{ que: 'algo', donde: '/keys' }],
    rps: [{ id: 'rp', legalName: 'RP', problems: [], services: [{ id: 's', name: 'S', uses: [{ published: true }] }] }],
    svg: '<svg/>',
  },
  keysPage: {
    keys: [{ name: 'k', subject: 'CN=x', encrypted: true, role: 'CA', ca: true, notAfter: '2030-01-01', tlso: null }],
    cas: ['k'],
    roles: { r: { profile: 'p', label: 'L', lista: 'X', eku: null, requiresCa: null } },
    schemes: [{ id: 's', displayName: 'S' }],
  },
};

let fallos = 0;
console.log('VISTAS: se renderizan sin referencias rotas\n');
for (const [nombre, args] of Object.entries(MINIMOS)) {
  for (const [etiqueta, datos] of [['vacia', args], ['con datos', CON_DATOS[nombre]]]) {
    if (!datos) continue;
    try {
      const html = views[nombre](datos);
      if (typeof html !== 'string' || !html.includes('<')) throw new Error('no devuelve HTML');
      console.log(`  ok   ${nombre} (${etiqueta})`);
    } catch (e) {
      fallos += 1;
      console.log(`  FALLO ${nombre} (${etiqueta}) → ${e.message}`);
    }
  }
}
// El diagrama-resumen de la portada tiene su propio test de CONTENIDO, y no de
// "no revienta": cuando `estado` paso de objeto a array, `graphResumenSvg` siguio
// indexandolo por clave y degrado en silencio —`?? {}` y `?.` por todas partes—,
// asi que pinto todas las cajas en rojo, sin sus numeros y sin la sexta lista.
// Ni este test ni el de la consola lo cazaron: los dos miraban que la pagina se
// renderizara. La unica forma de que no vuelva a pasar es afirmar que cada pieza
// del estado ACABA dibujada.
{
  const { graphResumenSvg } = await import('../apps/console/graph-svg.mjs');
  const estado = [
    { k: 'tlso', grupo: 'firmante', pieza: 'Firmante de listas', donde: '/keys', ok: true, detalle: '2 conforme(s)' },
    { k: 'av-lab', grupo: 'lista', pieza: 'av-lab', donde: '/lists/av-lab', ok: true, detalle: '3 entrada(s) · #7' },
    { k: 'pubeaa-lab', grupo: 'lista', pieza: 'pubeaa-lab', donde: '/lists/pubeaa-lab', ok: false, detalle: 'vacia' },
    { k: 'rps', grupo: 'rps', pieza: 'Relying parties', donde: '/rps', ok: false, parcial: true, detalle: '1/2 validas' },
    { k: 'certs', grupo: 'certs', pieza: 'Certificados emitidos', donde: '/rps', ok: false, detalle: 'ninguno emitido' },
  ];
  const svg = graphResumenSvg(estado);
  const faltan = estado.filter((e) => !svg.includes(e.pieza) || !svg.includes(e.detalle));
  if (faltan.length) {
    fallos += 1;
    console.log(`  FALLO graphResumenSvg → no dibuja: ${faltan.map((e) => e.pieza).join(', ')}`);
  } else {
    console.log('  ok   graphResumenSvg dibuja cada pieza del estado, con su detalle');
  }
  // Y los tres colores salen del estado, no de un default: una lista lista en
  // verde, una vacia en rojo y las relying parties a medias en ambar.
  const colores = ['var(--ok)', 'var(--bad)', 'var(--warn)'].every((c) => svg.includes(c));
  if (colores) console.log('  ok   graphResumenSvg colorea segun ok/parcial/pendiente');
  else { fallos += 1; console.log('  FALLO graphResumenSvg no colorea por estado'); }
}

console.log(fallos ? `\n${fallos} FALLO(S)` : '\nTODO OK');
process.exit(fallos ? 1 : 0);
