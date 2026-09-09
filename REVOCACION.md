# Revocación — nota de diseño

> **Estado: propuesta.** Nada de lo que describe la §4 en adelante está
> implementado. Sí lo están las dos piezas de la §1 marcadas ✅: la status list
> de los WRPRC y la baja de una entidad en una lista. Esta nota existe para que
> la decisión y sus motivos queden escritos antes de tocar código —
> 2026-09-09.

## 0. La pregunta, y la respuesta corta

Queremos poder **revocar**, y que revocar signifique algo comprobable desde
fuera: que un verificador o una wallet cambie su veredicto. La pregunta que lo
abre todo es si eso es "montar CRLs".

La respuesta es que **no hay un mecanismo, hay tres**, y la norma elige uno por
tipo de artefacto: la status list para los WRPRC, la propia lista de confianza
para las anclas, y la CRL para los certificados X.509. Dos de los tres ya
existen en este laboratorio. Lo que falta es el tercero, y falta entero.

La regla que se propone adoptar es la más simple que cubre el despliegue:

> **Toda hoja que emita este laboratorio cuelga de una CA y es revocable por la
> CRL de esa CA. Toda CA publica su CRL desde el primer día, aunque esté
> vacía.**

Esa regla no es gratis: obliga a una jerarquía de dos niveles, deja fuera los
certificados autofirmados y exige reemitir lo ya emitido. Las tres
consecuencias están en la §3.

## 1. Tres mecanismos, uno por artefacto

| Artefacto | Mecanismo que fija la norma | Hoy |
|---|---|---|
| **WRPRC** (JWT de TS 119 475) | **Token Status List.** §6.2.3.10, NOTE 1: *«WRPRC providers do not provide OCSP or CRL service»*. El §6.2.6.2 fija además el detalle: array de bits, referencia `{uri, idx}` dentro del propio certificado, semántica `valid`/`revoked`, lista firmada | ✅ implementado |
| **Anclas de una lista LoTE** (PID, Wallet, WRPAC, WRPRC providers) | **Quitar la entidad y reemitir la lista.** TS 119 602, anexos D/E/F/G: *«The ServiceStatus component shall not be used»*, y *«When a listed WRPAC provider does not have that mandate anymore, it shall be removed from the list»*. No hay estado intermedio: se está o no se está | ✅ existe (`remove-provider` + reemitir); falta **llamarlo** revocación |
| **Ancla de la AV Trusted List** (XML) | **Estado `deprecated`** + `StatusStartingTime`. Perfil de la Comisión, tabla I.3: `recognized` o `deprecated`, *«to the exclusion of any other»* | ⚠️ el constructor ya emite ambos campos; no hay operación que los ponga, y `setProviders` los pisa |
| **Anclas de la lista PubEAA** (`pubeaa-lab`) | Estado **`withdrawn`**. Es la única lista LoTE cuyo `ServiceStatus` *shall be present*, y el anexo H manda ponerlo en **todos** los servicios de la entidad cuando deja de estar notificada | ❌ no hay operación que lo ponga; hoy toda entrada se emite `notified` |
| **Certificados X.509**: access certificates (WRPAC), Document Signers, firmantes de listas y de credenciales, sub-CAs | **CRL** (o OCSP). TS 119 411-8 §6.6.2 y §6.6.3 heredan de EN 319 411-1 los perfiles de CRL y de OCSP; REV-6.3.9-04: *«shall revoke any wallet-relying party access certificate when the registration of the wallet-relying party is suspended or cancelled»* | ❌ **no existe** |

Dos lecturas que conviene no perder:

- **Para los WRPRC la CRL está explícitamente descartada por la norma.** No es
  que no hayamos llegado: es que ahí no va.
- **Para las anclas, la lista de confianza *es* el mecanismo de revocación.** Un
  ancla fuera de la lista no la valida nadie, sin necesidad de CRL. Por eso la
  CRL de una hoja publicada como ancla es, para el veredicto, un cinturón
  encima de los tirantes — lo cual no la hace inútil (§7), pero sí secundaria.

## 2. Inventario: qué emite este laboratorio y quién podría revocarlo

| Se emite con | Qué es | Emisor hoy | ¿Revocable por CRL? |
|---|---|---|---|
| `mint-ca` | CA raíz (IACA, Access CA, CA de firmantes) | autofirmada | **No** — es el ancla; se retira sacándola de la lista (§3.4) |
| `mint-leaf <ca>` | hoja genérica | esa CA | ✅ |
| `mint-signer <ca> … mdoc-ds` \| `pid-ds` \| `pubeaa-ds` | Document Signer | la IACA | ✅ |
| `mint-signer <ca> … wrprc` \| `wia` \| `key-attestation` | firmante de credenciales | esa CA | ✅ |
| `mint-signer - … wrprc` \| `wia` \| `key-attestation` | el mismo, **autofirmado** | ninguno | ❌ (§3.2) |
| `mint-tl-signer` | TLSO (firma las listas) | **autofirmado siempre** | ❌ (§3.3) |
| `mint-wrpac` | access certificate del RP | la Access CA | ✅ |
| — | sub-CA | **no se puede emitir hoy** | (§3.1) |

De las ocho filas, cinco son ya revocables en cuanto exista la maquinaria, dos
no lo son por construcción y una no existe. La lista de PubEAA no añade una
fila: su Document Signer cuelga de una IACA como los demás. Lo que sí añade es
la **segunda** forma de revocar un ancla (`withdrawn`, §1), que hasta que esa
lista existió no tenía ocupante. La regla de la §0 obliga a mover
esas tres.

## 3. Consecuencias de "toda hoja revocable"

### 3.1 Hace falta jerarquía, y hoy está prohibida por un `pathLen`

Para que una CA sea revocable tiene que colgar de otra. Eso significa **sub-CAs**
(`mint-ca --issuer <raíz>`), que hoy no existen: `mintCa` siempre autofirma.

Y hay un detalle que muerde: `mintCa` emite `BasicConstraints(CA:TRUE, pathLen:
0)`, y `pathLen 0` **prohíbe cualquier CA por debajo**. Comprobado con OpenSSL
sobre una jerarquía de tres niveles: `error 25 at 2 depth: path length
constraint exceeded`. Una raíz destinada a emitir sub-CAs tiene que salir con
`pathLen: 1`.

Propuesta: `mint-ca` sigue dando `pathLen 0` por defecto (una CA que solo emite
hojas es lo normal y lo más estrecho), y `--issuer` implica subir el `pathLen`
de la raíz que la emite… lo cual no se puede hacer a posteriori sin reemitir la
raíz. Así que en la práctica: **la decisión de si una raíz va a tener sub-CAs se
toma al crearla** (`mint-ca --path-len 1`), y quien no la tome se queda con un
nivel. Documentarlo es más honesto que esconderlo tras una reemisión silenciosa
del ancla — reemitir la raíz invalida todo lo que cuelga de ella.

### 3.2 Un certificado autofirmado no es revocable, y no es un descuido

Dos razones independientes, y cualquiera de las dos basta:

1. **No tiene `cRLSign`.** Nuestras hojas llevan KeyUsage `digitalSignature` a
   secas (es lo que exige su perfil), y RFC 5280 pide `cRLSign` en quien firma
   una CRL. Un verificador estricto rechaza esa CRL.
2. **Aunque lo llevara, no protegería de nada.** El caso que la revocación
   tiene que cubrir es "esta clave está comprometida", y quien tiene la clave
   comprometida firma también su propia CRL — incluida una que diga que todo
   está bien.

Así que la regla de la §0 implica: **un firmante que quiera ser revocable no
puede ser autofirmado.** La regla de las tres opciones que documenta el
`MANUAL.md` (autofirmado legítimo cuando la lista publica el certificado
firmante) sigue siendo cierta desde el punto de vista del anclaje, pero ahora
tiene un contrapeso que hay que decir en la interfaz: *autofirmado = no
revocable*. La consola debería mostrarlo como una propiedad del certificado, al
lado del perfil, y el grafo pintarlo (una hoja sin arista a ninguna CRL).

No se propone prohibir el autofirmado: se propone **etiquetarlo**, y ofrecer
"reemitir bajo una CA" como acción a un clic. En un laboratorio, poder montar
el escenario no revocable es parte del material de pruebas.

### 3.3 El TLSO: la norma admite las dos formas

TS 119 612 §5.7.1, literal: *«The Issuer shall be the TLSO itself (i.e. a
self-signed certificate) **or a TSP trust service listed in the TL** or in one
of the TL that is part of the same community»*.

O sea que un TLSO emitido por una CA **listada en la propia lista** es
conforme, y revocable. El problema es que en la AV TL los servicios listados
son PAAPs: meter ahí una CA solo para que emita el firmante distorsiona la
lista que estamos imitando. Y §5.7.1 remata que el `ds:KeyInfo` no puede llevar
cadena, así que el consumidor pinea el certificado suelto.

Propuesta: **`mint-tl-signer` sigue autofirmando por defecto** y gana un
`--issuer` opcional que avisa de la divergencia. La revocación real de un TLSO
es cambiar el pin y reemitir; la CRL, aquí, es material de pruebas (§7).

### 3.4 Las raíces no se revocan: se sacan de la lista

Una raíz autofirmada tendría que firmar su propia revocación, lo que no
significa nada. Su mecanismo de retirada es el de la §1: desaparecer de la
lista de confianza (LoTE) o pasar a `deprecated` (AV TL). Es coherente con lo
que ya hacemos y no necesita nada nuevo.

### 3.5 Lo ya emitido no lleva CDP: hay que reemitirlo

Un verificador encuentra la CRL por la extensión `crlDistributionPoints` **del
certificado que está comprobando**. Los certificados ya emitidos no la llevan,
y no se les puede añadir sin reemitirlos (cambiaría la firma). Mismo aviso que
con las listas: *esto no publica solo, hay que reemitir*. La consola debería
listar qué certificados vivos están "fuera de cobertura" por no tener CDP.

## 4. Viabilidad: verificada, no supuesta

Todo lo que sigue se probó con las dependencias que el repo **ya** tiene
(`@peculiar/x509` 2.1.0 trae `X509CrlGenerator`; `@peculiar/asn1-x509` trae
`CRLNumber`), contra OpenSSL 3.0 como tercero independiente.

Jerarquía de tres niveles (raíz `pathLen 1` → sub-CA → hoja), CDP en cada
certificado emitido, una CRL por CA:

| Escenario | `openssl verify -crl_check_all` |
|---|---|
| A. Nada revocado (las dos CRL vacías o sin la entrada) | `OK` |
| B. La raíz revoca la sub-CA (`cACompromise`) | `error 23 at 1 depth: certificate revoked` |
| C. La sub-CA revoca la hoja (`privilegeWithdrawn`) | `error 23 at 0 depth: certificate revoked` |

Tamaños: **294 bytes** una CRL con una entrada, **242 bytes** una vacía. Publicar
una CRL por CA desde el primer día no cuesta nada, y es lo que distingue "no hay
nada revocado" de "no hay CRL" — distinción que decide el veredicto de cualquier
consumidor que falle en abierto.

### 4.1 Cuatro tropiezos que ya salieron

1. **`@peculiar/x509` etiqueta el PEM `-----BEGIN CRL-----`; OpenSSL exige
   `-----BEGIN X509 CRL-----`** y con la otra etiqueta responde *"unable to load
   CRL"*. Se sirve DER (`application/pkix-crl`, que además es lo que pide el
   `Accept` de los clientes) y se reetiqueta al exportar a fichero.
2. **`mintCa(…, { crlUri })` pone el CDP en el certificado de la CA**, que es
   justo donde no sirve: ahí significaría "dónde publica *mi emisor* mi
   revocación", y en una raíz autofirmada no significa nada. El CDP va en la
   **hoja emitida**. Como ningún llamante pasa hoy ese parámetro, corregirlo no
   rompe nada.
3. **El almacén de artefactos es texto** (`body text NOT NULL` en SQL, ficheros
   de texto en el otro adaptador). La CRL sería el primer artefacto binario:
   se guarda en base64 con su marca de codificación y el publisher decodifica
   al servir. Sigue siendo "guardar el byte, no la receta".
4. **`setProviders` reconstruye cada entrada sin copiar `status`**: deprecar un
   ancla de la AV TL y luego tocar la lista la resucita. Hay que preservarlo (y
   con él `statusStartingTime`) antes de que exista la operación de deprecar.

## 5. Perfil de la CRL

RFC 5280, versión 2, y nada más:

- `signatureAlgorithm` ECDSA-SHA256, la misma curva que todo lo demás.
- `thisUpdate` / `nextUpdate` — `nextUpdate` es obligatorio para nosotros
  aunque RFC lo haga opcional: sin él, un consumidor no puede distinguir una
  CRL fresca de una rancia, que es el mismo problema que el `NextUpdate` de la
  AV TL.
- **`crlNumber`** (2.5.29.20), monótono por CA. Lo pide la §5.2.3 y no lo pone
  el generador: hay que añadirlo como extensión.
- **`authorityKeyIdentifier`** (§5.2.1), también a mano.
- Entradas con **`reasonCode`**. Mapeo propuesto:
  | Situación | Código |
  |---|---|
  | El registro del RP se suspende o se cancela (REV-6.3.9-04) | `privilegeWithdrawn` (9) |
  | Los datos registrados dejan de ser exactos (REV-6.2.3.9-07) | `affiliationChanged` (3) |
  | Clave comprometida | `keyCompromise` (1) |
  | Sub-CA comprometida | `cACompromise` (2) |
  | Rotación: se emitió un reemplazo | `superseded` (4) |
  | El proveedor deja de operar | `cessationOfOperation` (5) |

  `certificateHold` (6) queda fuera: la norma resuelve la suspensión del
  registro **revocando** («suspended *or* cancelled»), así que no hace falta un
  estado reversible.
- Una entrada **no se borra**. La única baja legítima es cuando el certificado
  ya caducó (RFC 5280 lo permite), y aun así conviene no hacerlo: es el mismo
  criterio que las posiciones de la status list, que nunca se reciclan.

Fuera del perfil: delta CRLs, `IssuingDistributionPoint`, y CRLs indirectas.
Complican al consumidor y no aportan nada a un laboratorio.

## 6. Modelo de datos y superficies

Simétrico a las status lists, que es el patrón que ya funciona en el repo.

**Documento de estado**, uno por CA:

```jsonc
{
  "kind": "x509-crl",
  "issuerKey": "access-ca",              // quién la firma: lo impone el documento
  "url": "https://trust-lab.espuni.com/crl/access-ca.crl",
  "crlNumber": 7,
  "validityDays": 7,
  "entries": {
    "f842dadbe879e66e": {                 // serial en hex, tal cual va en el cert
      "subject": "C=ES, O=Lab S.L., CN=RP access cert",
      "keyName": "lab-rp-svc-1-access",   // informativo: puede no existir ya
      "revokedAt": "2026-09-09T09:55:20Z",
      "reason": "privilegeWithdrawn",
      "note": "registro cancelado por el registrar"
    }
  }
}
```

**La entrada sobrevive a la clave.** Es la lección de las posiciones: si el
rastro viviera en el documento de la clave, borrar la clave desrevocaría el
certificado — y el certificado sigue existiendo ahí fuera, en manos de quien lo
tenga.

**Operaciones** (`packages/ops`), todas con la misma forma que las de status:

- `createCrl(store, { id, issuerKey, url, validityDays })` — se crea sola al
  emitir una CA, o a mano para una CA importada.
- `revokeCert(store, { caId, name | serial, reason, note })` — resuelve el
  serial desde la clave si se da el nombre; **no publica**.
- `buildCrl(store, crypto, { id })` — incrementa `crlNumber`, firma con
  `issuerKey` (el firmante lo impone el documento, no quien pulsa el botón) y
  **se relee antes de guardar**: `crl.verify()` contra el certificado de la CA
  y `findRevoked()` de cada entrada. Un artefacto que no se verifica es un
  artefacto cuyo formato nadie comprueba.
- `checkRevoked(store, { caId, serial })` — lee el artefacto publicado, no el
  documento, que es lo que ve el mundo.

**Emisión con CDP**: `mintLeaf`, `mintRoleSigner` y `mintWrpac` reciben el
`crlUri` del documento CRL de su CA. Sin CDP el consumidor no encuentra la
lista y —esto está medido en EUDIPLO— **da el certificado por bueno**.

**Publisher**: `KIND_OF['x509-crl'] = 'crl'`, `ROUTES.crl` con
`application/pkix-crl`, cuerpo binario, `Cache-Control` acotado por
`nextUpdate`, y ruta **declarada por el documento** como el resto — la URL viaja
dentro del CDP de cada certificado emitido, así que servir en otro sitio deja
firmado un puntero a un 404.

**Consola**: cada CA gana su sección con su CRL (posiciones ocupadas, número de
CRL, última emisión) y cada clave que cuelgue de ella un botón **Revocar** al
lado del de Borrar. No son lo mismo y conviene que se vea: *borrar* quita el
material de la fábrica, *revocar* **publica** que ya no vale. En el grafo, la
CRL es un nodo propio con arista a su CA, como las status lists.

**CLI**: `new-crl <id> <ca> <url>`, `revoke <ca> <clave|serial> <motivo>`,
`crl-build <id>`, `crl-check <id> <serial>`.

**Tests**: unidad (firma, `findRevoked`, número monótono), e2e del CLI
(revocar → reemitir → comprobar), y **contraste con OpenSSL en CI** — está en
los runners de GitHub y en el contenedor, y es para la CRL lo que "todo lo
firmado se relee" es para el resto: un tercero que no comparte nuestro código.

## 7. La CRL como banco de pruebas

Lo interesante de un laboratorio no es tener CRL: es poder publicar **una CRL
mala a propósito** y medir qué hace el consumidor. Los casos que quedarían
disponibles, en la línea de los cuatro del laboratorio ZK:

1. Certificado revocado, CRL fresca y bien firmada → ¿lo rechaza?
2. CRL **caducada** (`nextUpdate` pasado) → ¿falla en abierto o en cerrado?
3. CDP que responde **404** → ídem.
4. CRL firmada por **otra** CA que no emitió el certificado → ¿comprueba la
   firma, o le basta con que el fichero parsee?
5. Serial con el **bit alto a 1** (la mitad de los seriales aleatorios) →
   ¿normaliza el padding del INTEGER DER? (§8)
6. Certificado **sin CDP** → ¿lo da por bueno en silencio?

Los casos 2 a 6 son los que separan "implementa CRL" de "comprueba
revocación". Ninguno se puede montar sin ser el emisor.

## 8. Lo que ya encontramos en el consumidor

EUDIPLO tiene el lado consumidor escrito (`CrlValidationService`): lee el CDP,
descarga DER, cachea por `nextUpdate`. Pasando por él la CRL del spike:

```
serial del certificado : f842dadbe879e66e
serial en la CRL       : 00f842dadbe879e66e   ← padding del INTEGER DER
¿lo da por revocado?   : no
```

Con la **misma** CRL, OpenSSL dice `certificate revoked`. Tres observaciones,
por orden de gravedad:

1. **Compara el serial en hexadecimal sin normalizar el byte de padding**, así
   que un certificado revocado cuyo serial tenga el bit alto a 1 —la mitad de
   los seriales aleatorios— se lee como válido.
2. **No verifica la firma de la CRL** en ningún punto: parsea la
   `CertificateList` y compara seriales. Quien pueda servir esa URL puede
   des-revocar.
3. `validateCertificate`, el único método que usa el servicio, **no lo llama
   nadie** en el árbol (ni hay tests). Hoy es código muerto, así que ninguna de
   las dos cosas anteriores tiene efecto — y ninguna se notará el día que
   alguien lo cablee.

Consecuencia honesta para la prioridad: **publicar una CRL no cambia hoy ningún
veredicto en nuestro propio stack.** Su valor es medir qué hace la **wallet**
(que es lo que no se puede saber de otra forma), completar el marco, y —ya
demostrado— encontrar defectos como estos antes de que importen.

## 9. Plan por fases

| Fase | Qué | Por qué en ese orden | Esfuerzo |
|---|---|---|---|
| **F1** | CRL de la Access CA + CDP en los WRPAC + publisher + CLI + tests con OpenSSL | Es la única con base normativa dura (TS 119 411-8) y consumidor externo real: la wallet | ~½ jornada |
| **F2** | Extender a todas las CAs: DS de mdoc bajo IACA, firmantes de credenciales, `mint-ca --issuer` con `pathLen`, etiqueta *no revocable* en los autofirmados | Es la regla de la §0 completa | ~½ jornada |
| **F3** | Estados de servicio: `deprecated` en la AV TL y `withdrawn` en `pubeaa-lab`, preservando `status` en `setProviders` (+ `ServiceHistory` en el XML) | Cierra la revocación de anclas en las dos listas que la expresan con un estado en vez de con una baja | ~2 h |
| **F4** | Nombrar "quitar de la lista" como revocación en la consola; declarar el servicio `…/WRPAC/Revocation` con su `ServiceSupplyPoint` apuntando a la CRL | Hasta ahora no se emitía porque no había nada real que declarar; con F1 ya lo hay | ~1 h |
| **F5** | Los casos torcidos de la §7 como material de laboratorio | Es donde está el valor de medida | ~½ jornada |

## 10. Fuera de alcance, y por qué

- **OCSP.** Es un servicio en línea con su responder, su certificado, su perfil
  y su disponibilidad. La norma pide un servicio de estado, no OCSP en
  concreto; la CRL es un fichero firmado estático y encaja con lo que este
  laboratorio ya es: un publisher de solo lectura que sirve artefactos
  inmutables.
- **Delta CRLs e `IssuingDistributionPoint`.** Optimización para CRLs enormes.
  La nuestra pesa 294 bytes.
- **Revocar el TLSO por CRL como mecanismo real.** Se cambia el pin y se
  reemite; la CRL del TLSO solo tiene sentido como caso de prueba.
- **Suspensión (`certificateHold`).** La norma resuelve la suspensión del
  registro revocando.

## 11. Fuentes

- ETSI TS 119 475 v1.2.1 (2026-03) — §6.2.3.9 (revocación), §6.2.3.10 (servicios
  de estado, NOTE 1), §6.2.6.2 (perfil de status list).
- ETSI TS 119 411-8 v1.1.1 (2025-10) — §6.3.9 (REV-6.3.9-02…04), §6.3.10,
  §6.6.2 y §6.6.3 (perfiles de CRL y OCSP, por referencia a EN 319 411-1).
- ETSI TS 119 602 v1.1.1 (2025-11) — anexos D, E, F, G (`ServiceStatus` *shall
  not be used*; retirada por eliminación), anexo H (PubEAA: `notified` /
  `withdrawn`), §6.6.7 (service supply points).
- ETSI TS 119 612 v2.4.1 — §5.7.1 (emisor del certificado del TLSO).
- *AV Trusted List Specifications* v1.1.0 (CE, DIGIT.B.3) — tabla I.3
  (`recognized` / `deprecated`).
- IETF RFC 5280 — §5 (perfil de CRL), §5.2.1 (AKI), §5.2.3 (CRL number),
  §5.3.1 (reason codes).
