// El grafo de dependencias del marco de confianza, calculado sobre el almacen.
//
// Es la razon de ser de la consola. Los formularios los podria sustituir un
// editor de JSON; lo que no se puede sustituir es saber QUE FALTA para poder
// emitir lo siguiente. Hoy ese grafo vive en la cabeza del operador y en el
// orden de los comandos, y es donde se cometen los errores caros: emitir una
// lista con un firmante que no cumple el perfil, o un WRPRC apuntando a una
// status list que no existe.
import { assertTlsoProfile } from '../../packages/ca/src/index.mjs';
import { assertRegistry } from '../../packages/registry/src/index.mjs';
import { assertAvProfile } from '../../packages/tl-xml/src/av-profile.mjs';
import { LIST_PROFILES } from '../../packages/lote/src/index.mjs';

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
        id: doc.id, kind: doc.kind, title: doc.schemeName ?? doc.id, type: 'AV Trusted List (XML)',
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
        id: doc.id, kind: doc.kind, title: doc.schemeName ?? doc.id,
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
        entries: revocadas, signers: conformes.map((s) => s.name),
        blockers: conformes.length ? [] : ['no hay ningun firmante conforme'],
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
          published: await published(store, 'wrprc', `${svc.serviceIdentifier}-${u.intendedUseIdentifier}`),
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
