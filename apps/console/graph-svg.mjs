// El grafo, dibujado. SVG generado en el servidor: sin CDN, sin build y sin
// libreria de layout — la consola no tiene ninguna de las tres y meter una
// aqui costaria mas que las cien lineas que ocupa hacerlo.
//
// El layout es por columnas porque el grafo YA tiene columnas: el marco de
// confianza es una jerarquia, no una maraña. De izquierda a derecha va la
// direccion de la confianza: quien firma → la lista → lo que la lista publica
// → lo que cuelga de ello → lo emitido.
const COL = { key_root: 0, list: 1, key_anchor: 2, key_leaf: 3, artifact: 4, status: 5 };
const W = 210, H = 46, GAP_X = 96, GAP_Y = 22, PAD = 26;

const esc = (s) => String(s ?? '').replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));

/** A que columna va cada nodo, segun su papel en el grafo y no su tipo. */
function columnOf(n, g) {
  if (n.type === 'status') return COL.status;   // carril propio, al final
  if (n.type === 'list') return COL.list;
  if (n.type === 'wrprc' || n.type === 'rp') return COL.artifact;
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

export function graphSvg(g, { dangling = [] } = {}) {
  const roto = new Set(dangling.map((d) => d.id));
  const cols = new Map();
  for (const n of g.nodes) {
    const c = columnOf(n, g);
    if (!cols.has(c)) cols.set(c, []);
    cols.get(c).push(n);
  }

  const pos = new Map();
  let maxRows = 0;
  for (const [c, list] of cols) {
    list.sort((a, b) => (a.type + a.label).localeCompare(b.type + b.label));
    maxRows = Math.max(maxRows, list.length);
    list.forEach((n, i) => pos.set(n.id, { x: PAD + c * (W + GAP_X), y: PAD + i * (H + GAP_Y) }));
  }
  const width = PAD * 2 + 6 * W + 5 * GAP_X;
  const height = PAD * 2 + maxRows * (H + GAP_Y);

  const edges = g.edges
    .map((e) => {
      const a = pos.get(e.from);
      const b = pos.get(e.to);
      if (!a || !b) return '';
      // La confianza se lee de izquierda a derecha, asi que la flecha se dibuja
      // del nodo mas a la izquierda al mas a la derecha, sea cual sea el
      // sentido en que el modelo guarda la arista.
      const [from, to] = a.x <= b.x ? [a, b] : [b, a];
      const x1 = from.x + W, y1 = from.y + H / 2, x2 = to.x, y2 = to.y + H / 2;
      const mx = (x1 + x2) / 2;
      const dashed = e.type === 'revocable-en' ? ' stroke-dasharray="4 3"' : '';
      return `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" fill="none"
        stroke="var(--dim)" stroke-width="1.2"${dashed} marker-end="url(#a)"/>
      <text x="${mx}" y="${(y1 + y2) / 2 - 5}" text-anchor="middle" class="edge">${esc(
        e.label ? `${e.type} ${e.label}` : e.type,
      )}</text>`;
    })
    .join('');

  const boxes = g.nodes
    .map((n) => {
      const p = pos.get(n.id);
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
