// El grafo de dependencias del marco de confianza, calculado sobre el almacen.
//
// Es la razon de ser de la consola. Los formularios los podria sustituir un
// editor de JSON; lo que no se puede sustituir es saber QUE FALTA para poder
// emitir lo siguiente. Hoy ese grafo vive en la cabeza del operador y en el
// orden de los comandos, y es donde se cometen los errores caros: emitir una
// lista con un firmante que no cumple el perfil, o un WRPRC apuntando a una
// status list que no existe.
import { assertTlsoProfile, describeKey } from '../../packages/ca/src/index.mjs';
import { assertRegistry } from '../../packages/registry/src/index.mjs';
import { assertAvProfile } from '../../packages/tl-xml/src/av-profile.mjs';
import { LIST_PROFILES } from '../../packages/lote/src/index.mjs';
import { wrprcArtifactId } from '../../packages/ops/src/index.mjs';

/** Un firmante de listas conforme a la clausula 5.7.1 es requisito de todo. */
export async function tlsoCandidates(store, state) {
  const names = await store.keys.list();
  const out = [];
  for (const name of names) {
    const doc = await store.keys.get(name);
    if (!doc?.crt?.length) continue;
    let verdict;
    try {
      // Sin esquema, la pregunta es "sirve como firmante" (estructural). Con
      // esquema, es "sirve como firmante DE ESTE esquema", que ademas exige
      // que el subject cuadre con su nombre y territorio.
      verdict = assertTlsoProfile(doc.crt[0], state ?? {}, { checkNaming: !!state });
    } catch {
      continue;
    }
    out.push({ name, subject: doc.subject, errors: verdict.errors, warnings: verdict.warnings });
  }
  return out;
}

/**
 * Claves que pueden firmar un WRPRC.
 *
 * NO es lo mismo que un firmante de listas. TS 119 475 no le pide al firmante
 * de un registration certificate el EKU `id-tsl-kp-tslSigning`: eso es de
 * TS 119 612 y solo aplica a quien firma listas. Exigirlo aqui cerraba el
 * marco: obligaba a firmar los WRPRC con el TLSO, que no encadena con la CA
 * declarada en la lista de prestadores de WRPRC, asi que la cadena no llegaba
 * a ninguna parte. Aqui la pregunta es la que corresponde: no ser CA y poder
 * firmar.
 */
export async function signingCandidates(store) {
  const out = [];
  for (const name of await store.keys.list()) {
    const doc = await store.keys.get(name);
    const cert = doc?.crt?.[0];
    if (!cert) continue;
    let d;
    try {
      d = describeKey(cert);
    } catch {
      continue;
    }
    if (d.role === 'ilegible' || d.ca) continue;
    out.push({ name, subject: doc.subject, role: d.role, expired: d.expired });
    // `role` distingue el firmante de listas del resto, que es lo que permite
    // excluirlo donde no pinta nada (emisor de una status list, por ejemplo).
  }
  return out;
}

async function published(store, kind, id) {
  const a = await store.artifacts.latest(kind, id);
  return a ? { sequence: a.sequence, nextUpdate: a.nextUpdate, stale: a.nextUpdate ? new Date(a.nextUpdate) < new Date() : null } : null;
}

/**
 * Estado de cada cosa publicable: si se puede emitir, que lo impide, y si lo
 * ya publicado ha caducado. Un `NextUpdate` vencido no es un aviso menor: el
 * procedimiento §4.1 de la especificacion de la AV TL manda devolver FAILED, y
 * el camino clasico de EUDIPLO falla cerrado con una lista rancia.
 */
export async function readiness(store) {
  const docs = await store.docs.list('*');
  const items = [];

  const signers = await tlsoCandidates(store, null);
  const conformes = signers.filter((s) => s.errors.length === 0);

  for (const doc of docs) {
    if (doc.kind === 'etsi-tl-xml') {
      const blockers = [];
      const propios = await tlsoCandidates(store, doc);
      const validos = propios.filter((s) => s.errors.length === 0);
      if (!validos.length) {
        blockers.push(
          propios.length
            ? `ningun firmante cumple la clausula 5.7.1 para este esquema (${propios[0].errors[0]})`
            : 'no hay ningun firmante: crea uno con usage trustList',
        );
      }
      if (!(doc.providers ?? []).length) blockers.push('la lista no tiene ningun proveedor (PAA)');
      for (const p of assertAvProfile({ ...doc, pointerToSelf: doc.pointerToSelf ?? true })) {
        blockers.push(p.split('\n')[0]);
      }
      items.push({
        id: doc.id, kind: doc.kind, title: doc.displayName ?? doc.schemeName ?? doc.id,
        schemeName: doc.schemeName ?? null, type: 'AV Trusted List (XML)',
        entries: (doc.providers ?? []).length, signers: validos.map((s) => s.name),
        blockers, published: await published(store, 'lists', doc.id), url: doc.url,
      });
    }

    if (doc.kind === 'lote-json') {
      const blockers = [];
      if (!conformes.length) blockers.push('no hay ningun firmante conforme');
      if (!(doc.providers ?? []).length) blockers.push('la lista no tiene ninguna entidad');
      const profile = LIST_PROFILES[doc.loteType];
      if (!profile) blockers.push(`tipo de lista desconocido: ${doc.loteType}`);
      items.push({
        id: doc.id, kind: doc.kind, title: doc.displayName ?? doc.schemeName ?? doc.id,
        schemeName: doc.schemeName ?? null,
        type: `LoTE · ${doc.loteType}`, entries: (doc.providers ?? []).length,
        signers: conformes.map((s) => s.name), blockers,
        published: await published(store, 'lote', doc.id), url: doc.url,
        nonNormative: profile?.nonNormative,
      });
    }

    if (doc.kind === 'token-status-list') {
      const revocadas = Object.values(doc.entries ?? {}).filter((e) => e.status !== 'valid').length;
      items.push({
        id: doc.id, kind: doc.kind, title: doc.id, type: 'Status list',
        entries: revocadas, signers: [],
        // Su firmante no se elige: lo impone el emisor declarado. Lo que
        // bloquea aqui no es "no hay firmante conforme" sino "no tiene emisor".
        blockers: doc.issuerKey ? [] : ['sin emisor asignado: asignalo en Revocacion'],
        issuerKey: doc.issuerKey ?? null, issuer: doc.issuer ?? null,
        published: await published(store, 'status', doc.id), url: doc.url,
      });
    }
  }

  return items;
}

/** Estado de cada relying party: si su registro valida y que certificados tiene. */
export async function rpReadiness(store) {
  const docs = await store.docs.list('*');
  const out = [];
  const keyNames = new Set(await store.keys.list());
  for (const doc of docs) {
    if (!doc.walletRelyingParty) continue;
    const problems = assertRegistry(doc);
    const wrp = doc.walletRelyingParty;
    const services = [];
    for (const svc of wrp.services ?? []) {
      const uses = [];
      for (const u of svc.intendedUses ?? []) {
        uses.push({
          id: u.intendedUseIdentifier,
          purpose: u.purpose?.[0]?.content,
          credentials: (u.credentials ?? []).length,
          statusIndex: doc.statusList?.indexByIntendedUse?.[u.intendedUseIdentifier],
          artifactId: wrprcArtifactId(doc.id, svc.serviceIdentifier, u.intendedUseIdentifier),
          published: await published(store, 'wrprc', wrprcArtifactId(doc.id, svc.serviceIdentifier, u.intendedUseIdentifier)),
        });
      }
      // La convencion de nombre la fija `issueWrpac`: si esa clave existe, el
      // access certificate de este servicio esta emitido y es descargable.
      const accessKey = `${doc.id}-${svc.serviceIdentifier}-access`;
      services.push({
        id: svc.serviceIdentifier, name: svc.serviceTradeName, uses,
        accessKey: keyNames.has(accessKey) ? accessKey : null,
      });
    }
    out.push({ id: doc.id, legalName: wrp.legalName, problems, services });
  }
  return out;
}

/**
 * El estado del marco, resumido para la portada.
 *
 * Responde una sola pregunta —"¿esta montado?"— y por eso no lleva acciones:
 * cada pieza dice si esta, si esta a medias o si falta, y donde se arregla. El
 * detalle y los botones viven en su pantalla.
 */
export async function resumen(store) {
  const docs = await store.docs.list('*');
  const items = await readiness(store);
  const porId = new Map(items.map((i) => [i.id, i]));
  const firmantes = (await tlsoCandidates(store, null)).filter((s) => !s.errors.length);
  const rps = await rpReadiness(store);

  const deLista = (id) => {
    const i = porId.get(id);
    if (!i) return { ok: false, detalle: 'no existe' };
    if (!i.entries) return { ok: false, detalle: 'vacia' };
    if (!i.published) return { ok: false, parcial: true, detalle: `${i.entries} entrada(s), sin publicar` };
    return { ok: true, detalle: `${i.entries} entrada(s) · #${i.published.sequence}` };
  };

  const listas = ['av-lab', 'pid-lab', 'wallet-lab', 'wrpac-lab', 'wrprc-lab', 'pubeaa-lab'];
  const estado = {
    tlso: firmantes.length
      ? { ok: true, detalle: `${firmantes.length} conforme(s)` }
      : { ok: false, detalle: 'no hay ninguno' },
    av: deLista('av-lab'),
    pid: deLista('pid-lab'),
    wallet: deLista('wallet-lab'),
    wrpac: deLista('wrpac-lab'),
    wrprc: deLista('wrprc-lab'),
    pubeaa: deLista('pubeaa-lab'),
  };

  const validas = rps.filter((r) => !r.problems.length).length;
  estado.rps = rps.length
    ? { ok: validas === rps.length, parcial: validas > 0, detalle: `${validas}/${rps.length} validas` }
    : { ok: false, detalle: 'ninguna dada de alta' };

  let access = 0;
  let wrprcEmitidos = 0;
  for (const rp of rps) {
    for (const s of rp.services) {
      if (s.accessKey) access += 1;
      wrprcEmitidos += s.uses.filter((u) => u.published).length;
    }
  }
  estado.certs = access + wrprcEmitidos
    ? { ok: true, detalle: `${access} acceso · ${wrprcEmitidos} registro` }
    : { ok: false, detalle: 'ninguno emitido' };

  // Lo que falta, en el orden en que hay que resolverlo.
  const faltan = [];
  if (!firmantes.length) faltan.push({ que: 'Un firmante de listas', donde: '/keys' });
  for (const id of listas) {
    const i = porId.get(id);
    if (!i) continue;
    if (!i.entries) faltan.push({ que: `${i.title} esta vacia`, donde: `/lists/${id}` });
    else if (!i.published) faltan.push({ que: `${i.title} sin publicar`, donde: `/lists/${id}` });
    else if (i.published.stale) faltan.push({ que: `${i.title} caducada`, donde: `/lists/${id}` });
  }
  const sinEmisor = docs.filter((d) => d.kind === 'token-status-list' && !d.issuerKey);
  for (const d of sinEmisor) {
    faltan.push({ que: `La status list ${d.id} no tiene emisor`, donde: '/wrprc' });
  }
  for (const rp of rps) {
    if (rp.problems.length) {
      faltan.push({ que: `${rp.legalName}: ${rp.problems.length} problema(s) en el registro`, donde: `/docs/${rp.id}` });
    }
  }

  return { estado, faltan, rps };
}
