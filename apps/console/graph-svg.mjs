// El grafo, dibujado. SVG generado en el servidor: sin CDN, sin build y sin
// libreria de layout — la consola no tiene ninguna de las tres y meter una
// aqui costaria mas que las cien lineas que ocupa hacerlo.
//
// El layout es por columnas porque el grafo YA tiene columnas: el marco de
// confianza es una jerarquia, no una maraña. De izquierda a derecha va la
// direccion de la confianza: quien firma → la lista → lo que la lista publica
// → lo que cuelga de ello → lo emitido.
// `rp` y `wrprc` iban juntos, y sus aristas quedaban DENTRO de una columna:
// se dibujaban saliendo por la derecha de una caja para volver a la izquierda
// de otra, cruzando todo lo que hubiera en medio.
const COL = { key_root: 0, list: 1, key_anchor: 2, key_leaf: 3, rp: 4, wrprc: 5, status: 6 };
const N_COLS = 7;
const W = 210, H = 46, GAP_X = 96, GAP_Y = 22, PAD = 26;

const esc = (s) => String(s ?? '').replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));

/** A que columna va cada nodo, segun su papel en el grafo y no su tipo. */
function columnOf(n, g) {
  if (n.type === 'status') return COL.status;   // carril propio, al final
  if (n.type === 'list') return COL.list;
  if (n.type === 'wrprc') return COL.wrprc;
  if (n.type === 'rp') return COL.rp;
  if (n.type === 'orphan') return COL.key_anchor;
  const firma = g.edges.some((e) => e.to === n.id && e.type === 'firmada-por');
  if (firma) return COL.key_root;
  const listado = g.edges.some((e) => e.from === n.id && e.type === 'contenido-en');
  if (listado) return COL.key_anchor;
  return COL.key_leaf;
}

// Los colores salen de las variables que la consola ya define; no se inventan
// tokens nuevos solo para esta pagina.
const STYLE = {
  key: { fill: 'var(--surface-2)', stroke: 'var(--border)' },
  list: { fill: '#58a6ff1a', stroke: 'var(--accent)' },
  rp: { fill: 'var(--surface-2)', stroke: 'var(--border)' },
  wrprc: { fill: 'var(--surface-2)', stroke: 'var(--border)' },
  orphan: { fill: '#da36331a', stroke: 'var(--bad)' },
  status: { fill: '#d299221a', stroke: 'var(--warn)' },
};

/**
 * Ordena cada columna por el baricentro de sus vecinos (heuristica de Sugiyama).
 *
 * Con las cajas en orden alfabetico, las flechas se cruzan porque el alfabeto
 * no tiene nada que ver con quien apunta a quien. La idea es simple: cada caja
 * quiere estar a la altura media de las cajas con las que se conecta, asi que
 * se barre de izquierda a derecha y de vuelta unas cuantas veces, reordenando
 * cada columna segun donde estan sus vecinos en la anterior.
 *
 * No es optimo —minimizar cruces es NP-duro— pero es la heuristica estandar y
 * en un grafo de este tamano deja pocos.
 */
function ordenarPorBaricentro(cols, edges, pasadas = 6) {
  const columnas = [...cols.keys()].sort((a, b) => a - b);
  const colDe = new Map();
  for (const [c, list] of cols) for (const n of list) colDe.set(n.id, c);

  // Vecinos por columna: la arista se usa en los dos sentidos, porque lo que
  // importa para no cruzarse es la adyacencia, no la direccion.
  const vecinos = new Map();
  const anota = (a, b) => {
    if (!vecinos.has(a)) vecinos.set(a, []);
    vecinos.get(a).push(b);
  };
  for (const e of edges) {
    if (!colDe.has(e.from) || !colDe.has(e.to)) continue;
    anota(e.from, e.to);
    anota(e.to, e.from);
  }

  const indice = () => {
    const m = new Map();
    for (const list of cols.values()) list.forEach((n, i) => m.set(n.id, i));
    return m;
  };

  const barrer = (orden) => {
    const idx = indice();
    for (const c of orden) {
      const list = cols.get(c);
      const bary = new Map();
      for (const n of list) {
        // Solo cuentan los vecinos de columnas ya colocadas en esta pasada.
        const ref = (vecinos.get(n.id) ?? []).filter((v) =>
          orden.indexOf(colDe.get(v)) < orden.indexOf(c));
        bary.set(n.id, ref.length
          ? ref.reduce((acc, v) => acc + idx.get(v), 0) / ref.length
          : idx.get(n.id));
      }
      // Estable: sin vecinos que lo muevan, una caja se queda donde estaba.
      list.sort((a, b) => bary.get(a.id) - bary.get(b.id) || idx.get(a.id) - idx.get(b.id));
      list.forEach((n, i) => idx.set(n.id, i));
    }
  };

  for (let i = 0; i < pasadas; i += 1) {
    barrer(columnas);
    barrer([...columnas].reverse());
  }
}

/**
 * Parte cada arista larga en tramos de una columna, con un nodo virtual por
 * columna intermedia. Devuelve la ruta de cada arista original (para dibujarla
 * como polilinea) y el conjunto de tramos cortos (para ordenar).
 */
function insertarNodosVirtuales(cols, edges) {
  const colDe = new Map();
  for (const [c, list] of cols) for (const n of list) colDe.set(n.id, c);

  const rutas = new Map();
  const aristasCortas = [];
  let serie = 0;

  for (const e of edges) {
    const a = colDe.get(e.from);
    const b = colDe.get(e.to);
    if (a === undefined || b === undefined) continue;

    // La arista se recorre siempre de izquierda a derecha, que es como se
    // dibuja; el sentido logico ya lo lleva la etiqueta.
    const [ini, fin] = a <= b ? [e.from, e.to] : [e.to, e.from];
    const [ci, cf] = a <= b ? [a, b] : [b, a];
    const clave = `${e.from}\u0000${e.to}\u0000${e.type}`;

    if (cf - ci <= 1) {
      rutas.set(clave, [ini, fin]);
      aristasCortas.push({ from: ini, to: fin });
      continue;
    }

    const ruta = [ini];
    let previo = ini;
    for (let c = ci + 1; c < cf; c += 1) {
      const id = `virtual:${serie++}`;
      cols.get(c).push({ id, type: 'virtual', label: '' });
      colDe.set(id, c);
      ruta.push(id);
      aristasCortas.push({ from: previo, to: id });
      previo = id;
    }
    aristasCortas.push({ from: previo, to: fin });
    ruta.push(fin);
    rutas.set(clave, ruta);
  }
  return { rutas, aristasCortas };
}

export function graphSvg(g, { dangling = [] } = {}) {
  const roto = new Set(dangling.map((d) => d.id));
  const cols = new Map();
  for (const n of g.nodes) {
    const c = columnOf(n, g);
    if (!cols.has(c)) cols.set(c, []);
    cols.get(c).push(n);
  }

  // Orden inicial estable: alfabetico. El baricentro necesita un punto de
  // partida determinista, o el mismo grafo se dibuja distinto en cada carga.
  for (const list of cols.values()) {
    list.sort((a, b) => (a.type + a.label).localeCompare(b.type + b.label));
  }
  // Nodos virtuales para las aristas que saltan mas de una columna. Sin ellos
  // una arista larga es una diagonal recta que el ordenador de columnas no ve
  // —no tiene ningun extremo en las columnas que atraviesa— y se cruza con
  // todo lo que haya alli. Con ellos, la arista pasa a tener un punto en cada
  // columna intermedia y el baricentro puede apartarla. Es la mitad del
  // algoritmo de Sugiyama que faltaba.
  const { rutas, aristasCortas } = insertarNodosVirtuales(cols, g.edges);
  ordenarPorBaricentro(cols, aristasCortas);

  const pos = new Map();
  const maxRows = Math.max(...[...cols.values()].map((l) => l.length));
  for (const [c, list] of cols) {
    // Centrar verticalmente cada columna: con columnas de alturas muy
    // distintas, alinearlas todas arriba obliga a las aristas a bajar en
    // diagonal desde la columna corta, y esas diagonales son las que se cruzan
    // entre si.
    const offset = ((maxRows - list.length) * (H + GAP_Y)) / 2;
    list.forEach((n, i) =>
      pos.set(n.id, { x: PAD + c * (W + GAP_X), y: PAD + offset + i * (H + GAP_Y) }));
  }
  const width = PAD * 2 + N_COLS * W + (N_COLS - 1) * GAP_X;
  const height = PAD * 2 + maxRows * (H + GAP_Y);

  const edges = g.edges
    .map((e) => {
      const ruta = rutas.get(`${e.from}\u0000${e.to}\u0000${e.type}`);
      if (!ruta) return '';
      const puntos = ruta.map((id) => pos.get(id)).filter(Boolean);
      if (puntos.length < 2) return '';

      // Un tramo por par de puntos consecutivos. En los nodos virtuales la
      // linea entra y sale por el mismo punto medio, asi que la polilinea se
      // ve como una curva continua y no como una cadena de segmentos.
      const dashed = e.type === 'revocable-en' ? ' stroke-dasharray="4 3"' : '';
      let d = '';
      for (let i = 0; i < puntos.length - 1; i += 1) {
        const virtualIni = i > 0;
        const virtualFin = i < puntos.length - 2;
        const x1 = puntos[i].x + (virtualIni ? W / 2 : W);
        const y1 = puntos[i].y + H / 2;
        const x2 = puntos[i + 1].x + (virtualFin ? W / 2 : 0);
        const y2 = puntos[i + 1].y + H / 2;
        const mx = (x1 + x2) / 2;
        d += `${i === 0 ? `M${x1},${y1} ` : ''}C${mx},${y1} ${mx},${y2} ${x2},${y2} `;
      }
      // La etiqueta va en el primer tramo, junto al origen: en una arista
      // larga, ponerla en el centro geometrico la deja flotando lejos de los
      // dos extremos y sin decir de que arista es.
      const a = puntos[0], b = puntos[1];
      const lx = (a.x + W + b.x) / 2, ly = (a.y + b.y) / 2 + H / 2 - 5;
      return `<path d="${d.trim()}" fill="none" stroke="var(--dim)" stroke-width="1.2"${dashed}
        marker-end="url(#a)"/>
      <text x="${lx}" y="${ly}" text-anchor="middle" class="edge">${esc(
        e.label ? `${e.type} ${e.label}` : e.type,
      )}</text>`;
    })
    .join('');

  const boxes = g.nodes
    .map((n) => {
      const p = pos.get(n.id);
      if (!p) return '';
      const st = roto.has(n.id) ? STYLE.orphan : STYLE[n.type] ?? STYLE.key;
      const sub =
        n.type === 'list'
          ? n.published
            ? `#${n.published.sequence} · ${n.entries} entrada(s)`
            : 'sin publicar'
          : n.type === 'orphan'
            ? 'sin clave privada'
            : n.type === 'status'
            ? `${n.gastadas}/${n.size} gastadas · ${n.revocadas} revocada(s)`
            : n.type === 'key'
              ? (n.ca ? 'CA' : 'hoja') + (n.expired ? ' · CADUCADO' : '')
              : n.type;
      return `<g><rect x="${p.x}" y="${p.y}" width="${W}" height="${H}" rx="8"
        fill="${st.fill}" stroke="${st.stroke}" stroke-width="1.4"/>
        <text x="${p.x + 12}" y="${p.y + 20}" class="n">${esc(n.label)}</text>
        <text x="${p.x + 12}" y="${p.y + 36}" class="s">${esc(sub)}</text></g>`;
    })
    .join('');

  return `<svg viewBox="0 0 ${width} ${height}" width="${width}" height="${height}"
    xmlns="http://www.w3.org/2000/svg" role="img" aria-label="grafo de dependencias">
    <defs><marker id="a" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0,0 L8,4 L0,8 z" fill="var(--dim)"/></marker></defs>
    <style>
      .n { font: 600 13px system-ui, sans-serif; fill: var(--text) }
      .s { font: 11px var(--mono); fill: var(--dim) }
      .edge { font: 10px var(--mono); fill: var(--dim) }
    </style>
    ${edges}${boxes}
  </svg>`;
}

export const COLUMN_TITLES = [
  'firma las listas', 'listas de confianza', 'anclas publicadas',
  'lo que cuelga de ellas', 'emitido', 'revocacion',
];


/**
 * El grafo, resumido: un nodo por tipo de pieza, no uno por objeto.
 *
 * El completo de `/graph` sirve para depurar una cadena concreta; en la portada
 * estorba. Aqui la pregunta es otra —"¿esta el marco montado?"— y se responde
 * con siete cajas que se pintan segun haya o falte, no con veintisiete.
 */
export function graphResumenSvg(estado) {
  const W2 = 172, H2 = 54, GX = 74, GY = 26, P2 = 20;
  const cols = [
    [{ k: 'tlso', t: 'Firmante de listas' }],
    [
      { k: 'av', t: 'AV Trusted List' },
      { k: 'pid', t: 'PID providers' },
      { k: 'wallet', t: 'Wallet providers' },
      { k: 'wrpac', t: 'WRPAC providers' },
      { k: 'wrprc', t: 'WRPRC providers' },
    ],
    [{ k: 'rps', t: 'Relying parties' }],
    [{ k: 'certs', t: 'Certificados emitidos' }],
  ];
  const filas = Math.max(...cols.map((c) => c.length));
  const width = P2 * 2 + cols.length * W2 + (cols.length - 1) * GX;
  const height = P2 * 2 + filas * (H2 + GY);

  const pos = new Map();
  cols.forEach((col, ci) => {
    const off = ((filas - col.length) * (H2 + GY)) / 2;
    col.forEach((n, ri) => pos.set(n.k, {
      x: P2 + ci * (W2 + GX), y: P2 + off + ri * (H2 + GY), ...n,
    }));
  });

  const aristas = [
    ['tlso', 'av'], ['tlso', 'pid'], ['tlso', 'wallet'], ['tlso', 'wrpac'], ['tlso', 'wrprc'],
    ['wrpac', 'rps'], ['wrprc', 'rps'], ['rps', 'certs'],
  ];
  const lineas = aristas
    .map(([a, b]) => {
      const p = pos.get(a), q = pos.get(b);
      const x1 = p.x + W2, y1 = p.y + H2 / 2, x2 = q.x, y2 = q.y + H2 / 2;
      const mx = (x1 + x2) / 2;
      const ok = estado[a]?.ok && estado[b]?.ok;
      return `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" fill="none"
        stroke="${ok ? 'var(--dim)' : 'var(--border)'}" stroke-width="1.2"
        ${ok ? '' : 'stroke-dasharray="4 4"'} marker-end="url(#b)"/>`;
    })
    .join('');

  const cajas = [...pos.values()]
    .map((n) => {
      const e = estado[n.k] ?? {};
      const [fill, stroke] = e.ok
        ? ['#3fb95018', 'var(--ok)']
        : e.parcial
          ? ['#d2992218', 'var(--warn)']
          : ['#da363310', 'var(--bad)'];
      return `<g><rect x="${n.x}" y="${n.y}" width="${W2}" height="${H2}" rx="9"
        fill="${fill}" stroke="${stroke}" stroke-width="1.5"/>
        <text x="${n.x + 12}" y="${n.y + 22}" class="rn">${esc(n.t)}</text>
        <text x="${n.x + 12}" y="${n.y + 40}" class="rs">${esc(e.detalle ?? '—')}</text></g>`;
    })
    .join('');

  return `<svg viewBox="0 0 ${width} ${height}" width="100%" style="max-width:${width}px"
    xmlns="http://www.w3.org/2000/svg" role="img" aria-label="resumen del marco">
    <defs><marker id="b" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
      <path d="M0,0 L8,4 L0,8 z" fill="var(--dim)"/></marker></defs>
    <style>
      .rn { font: 600 13px system-ui, sans-serif; fill: var(--text) }
      .rs { font: 11px var(--mono); fill: var(--dim) }
    </style>
    ${lineas}${cajas}
  </svg>`;
}
