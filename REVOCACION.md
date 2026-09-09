# Revocación — nota de diseño

> **Estado: propuesta.** Nada de lo que se propone de la §3 en adelante está
> implementado. Sí lo están las dos piezas de la §1 marcadas ✅: la status list
> de los WRPRC y la baja de una entidad en una lista. La §4 y la §8 no son
> propuesta: son mediciones hechas. Esta nota existe para que la decisión y sus
> motivos queden escritos antes de tocar código — 2026-09-09.

## 0. La pregunta, y la respuesta corta

Queremos poder **revocar**, y que revocar signifique algo comprobable desde
fuera: que un verificador o una wallet cambie su veredicto. La pregunta que lo
abre todo es si eso es "montar CRLs".

La respuesta es que **no hay un mecanismo, hay tres**, y la norma elige uno por
tipo de artefacto: la status list para los WRPRC, la propia lista de confianza
para las anclas, y la CRL para los certificados X.509. Dos de los tres ya
existen en este laboratorio. Lo que falta es el tercero, y falta entero.

La regla que se propone adoptar:

> **Toda CA del marco de confianza ofrece servicio de revocación de los
> certificados que emite.** No es un rasgo de algunas CAs ni una fase posterior:
> una CA sin CRL publicada es una CA incompleta, igual que una lista sin
> firmante. La CRL nace con la CA —vacía— y toda hoja sale con su `CDP`
> apuntando a ella.

Conviene separar dos cosas que se confunden con facilidad, porque la propuesta
es la primera y no la segunda:

- **Que una CA *ofrezca* revocación** — que publique el estado de lo que ha
  emitido. Esto es lo que pide la norma a cualquier emisor (TS 119 411-8 §6.3.10
  *Certificate Status Services*, §6.6.2 *CRL Profile*) y lo que esta nota
  propone para **todas** las CAs del despliegue, sin excepción.
- **Que una CA *sea* revocable** — que alguien por encima pueda anularla. Eso
  exige jerarquía, y para una raíz autofirmada no existe: se retira sacándola de
  la lista de confianza. Es un asunto aparte, opcional, y está en la §3.6.

La regla no sale gratis: obliga a que toda emisión lleve `CDP`, deja fuera los
certificados autofirmados —que no tienen CA que los revoque— y exige reemitir lo
ya emitido. Las consecuencias, una a una, en la §3.

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

## 2. Inventario

### 2.1 Las CAs del marco, y qué tendría que revocar cada una

Una CA es cualquier clave del almacén con `CA:TRUE` y `cRLSign`, que es lo que
emite `mint-ca`. En un despliegue completo del laboratorio hay al menos estas,
y **todas** entran en la regla:

| CA | Qué emite | Qué publicaría su CRL |
|---|---|---|
| **Access CA** (WRPAC) | access certificates de cada RP | el access certificate de un RP cuyo registro se suspende o se cancela — REV-6.3.9-04 |
| **IACA de AV** | Document Signers de las atestaciones de edad | un DS comprometido o retirado; en AV es **el único** estado que hay, porque la atestación no lleva status list |
| **IACA de PID** | Document Signers del PID | ídem |
| **IACA de PubEAA** | Document Signers de las PuB-EAA | ídem |
| **CA de firmantes** (si se usa en vez de autofirmar) | firmantes de WRPRC, WIA y Key Attestation | el firmante retirado, sin tener que reemitir la lista que lo publica |
| **CA del TLSO** (opcional, §3.4) | el certificado que firma las listas | un TLSO retirado |

A esas se suman las **anclas ajenas**: certificados de CA que están en una lista
sin que tengamos su clave privada (hoy el grafo ya los marca como huérfanos).
Ésas no entran en la regla — su estado lo publica su dueño, no nosotros—, pero
la consola debería distinguirlas de una CA nuestra sin CRL, que sí es un hueco.

### 2.2 Las hojas, y quién las revoca

| Se emite con | Qué es | Emisor hoy | ¿Quién publica su estado? |
|---|---|---|---|
| `mint-leaf <ca>` | hoja genérica | esa CA | la CRL de esa CA |
| `mint-signer <ca> … mdoc-ds` \| `pid-ds` \| `pubeaa-ds` | Document Signer | la IACA | la CRL de la IACA |
| `mint-signer <ca> … wrprc` \| `wia` \| `key-attestation` | firmante de credenciales | esa CA | la CRL de esa CA |
| `mint-wrpac` | access certificate del RP | la Access CA | la CRL de la Access CA |
| `mint-signer - … wrprc` \| `wia` \| `key-attestation` | el mismo, **autofirmado** | ninguno | **nadie** (§3.3) |
| `mint-tl-signer` | TLSO | **autofirmado siempre** | **nadie** hoy (§3.4) |
| `mint-ca` | CA raíz | autofirmada | **nadie**: se retira sacándola de la lista (§3.6) |

Cuatro de las siete filas quedan cubiertas por la misma maquinaria en cuanto
exista, porque la CRL es genérica: lo único que cambia es qué CA la firma. Las
tres restantes son autofirmadas, y ése es el hueco que la regla obliga a mirar
de frente (§3.3 y §3.4).

## 3. Consecuencias de "toda CA ofrece revocación"

### 3.1 La CRL nace con la CA, y se publica vacía

Si la revocación es una propiedad de la CA y no un añadido posterior, entonces
`mint-ca` crea el documento de CRL en el mismo acto, con su URL derivada del
identificador (`…/crl/<ca>.crl`) y sin ninguna entrada. Tres razones:

1. **La URL tiene que existir antes que la primera hoja.** El `CDP` viaja
   *dentro* de cada certificado emitido; si la CRL se creara después, todo lo
   emitido hasta entonces quedaría fuera de cobertura para siempre (§3.7).
2. **Una CRL vacía no es lo mismo que no tener CRL.** La primera dice "no hay
   nada revocado, y lo firmo"; la segunda no dice nada, y cada consumidor
   decide por su cuenta qué hacer con el silencio — que es justo lo que se
   quiere poder medir (§7). Cuesta 242 bytes.
3. **Una CA sin CRL es una CA incompleta.** Debería aparecer como hueco en la
   pantalla de estado, junto a "lista sin firmante" y "ancla sin clave", no
   como una casilla opcional que nadie mira.

### 3.2 Toda emisión lleva `CDP`, sin excepción

> **Qué es el `CDP`.** *CRL Distribution Point*: la extensión X.509
> `crlDistributionPoints` (OID 2.5.29.31, RFC 5280 §4.2.1.13). Va **dentro del
> certificado emitido**, firmada por la CA junto con todo lo demás, y dice
> **dónde se publica la CRL que cubre a ese certificado**. Es el mecanismo de
> descubrimiento: el verificador tiene el certificado en la mano, lee su `CDP`,
> descarga esa CRL y busca su número de serie.
>
> Es el equivalente exacto, en X.509, del `status.status_list = { uri, idx }`
> del WRPRC: **el puntero al estado viaja dentro del propio artefacto firmado**.
> De ahí las dos consecuencias que ordenan medio diseño — no se puede añadir
> después (cambiaría la firma, §3.7), y la URL de la CRL tiene que existir antes
> de emitir la primera hoja (§3.1).

Un verificador no busca la CRL: la encuentra —o no— por la extensión
`crlDistributionPoints` **del certificado que está comprobando**. Sin ella no
hay nada que consultar, y está medido que el consumidor entonces **da el
certificado por bueno**: EUDIPLO devuelve literalmente `isValid: true` con el
motivo *"No CRL Distribution Points in certificate"* (§8).

Así que el `CDP` deja de ser un parámetro opcional de `mintCa` —donde además
está en el sitio equivocado, §4.1— y pasa a ser algo que **la propia CA
impone** a todo lo que firma: `mintLeaf`, `mintRoleSigner` y `mintWrpac` lo
reciben del documento de CRL de su emisor, no de quien llama.

### 3.3 Un certificado autofirmado no tiene quien lo revoque

No es un defecto de implementación: no hay CA. Y aunque se quisiera forzar que
se revocara a sí mismo, no funcionaría, por dos razones independientes:

1. **No tiene `cRLSign`.** Nuestras hojas llevan KeyUsage `digitalSignature` a
   secas, que es lo que exige su perfil, y RFC 5280 pide `cRLSign` en quien
   firma una CRL. Un verificador estricto rechaza esa CRL.
2. **Aunque lo llevara, no protegería de nada.** El caso que la revocación
   tiene que cubrir es "esta clave está comprometida", y quien tiene la clave
   comprometida firma también la CRL — incluida una que diga que todo va bien.

La regla de las tres opciones del `MANUAL.md` (autofirmar es legítimo cuando la
lista publica el certificado firmante) sigue siendo cierta **para el anclaje**,
pero ahora tiene un contrapeso que la interfaz tiene que decir: *autofirmado =
sin servicio de revocación*. Ahí la única retirada posible es reemitir la lista
sin él, que es más lenta y más ruidosa — y en la AV TL, con `NextUpdate` de por
medio, puede tardar días en llegar a un consumidor que cachea.

No se propone prohibirlo: se propone **etiquetarlo** en la consola y en el
grafo (una hoja sin arista a ninguna CRL), y ofrecer *"reemitir bajo una CA"* a
un clic. Montar el escenario sin revocación es, en un laboratorio, material de
pruebas legítimo — pero tiene que verse que es ese escenario y no un descuido.

### 3.4 El TLSO: la norma admite las dos formas

TS 119 612 §5.7.1, literal: *«The Issuer shall be the TLSO itself (i.e. a
self-signed certificate) **or a TSP trust service listed in the TL** or in one
of the TL that is part of the same community»*.

O sea que un TLSO emitido por una CA **listada en la propia lista** es
conforme, y entonces esa CA le ofrece revocación como a cualquier otra hoja. El
problema es que en la AV TL los servicios listados son PAAPs: meter ahí una CA
solo para que emita el firmante distorsiona la lista que estamos imitando. Y
§5.7.1 remata que el `ds:KeyInfo` no puede llevar cadena, así que el consumidor
pinea el certificado suelto y no recorre nada.

Propuesta: **`mint-tl-signer` sigue autofirmando por defecto** y gana un
`--issuer` opcional, avisando de la divergencia. La retirada real de un TLSO es
cambiar el pin y reemitir; su CRL, aquí, es material de pruebas (§7).

### 3.5 Las anclas ajenas no entran en la regla

En una lista puede haber certificados de CA de los que no tenemos clave privada
—hoy el grafo ya los marca como huérfanos—. Su estado lo publica su dueño, y si
su certificado trae `CDP`, apunta a **su** CRL, no a la nuestra. La consola
tiene que distinguir los dos casos, porque se parecen en la pantalla y no se
parecen en nada más: *ancla ajena sin CRL nuestra* es normal; *CA nuestra sin
CRL* es un hueco del marco.

### 3.6 Que una CA sea revocable es otro asunto (y es opcional)

Ofrecer revocación y ser revocable son cosas distintas. Lo primero es la regla
de esta nota y no necesita jerarquía. Lo segundo sí: para anular una CA hace
falta otra por encima, es decir **sub-CAs** (`mint-ca --issuer <raíz>`), que hoy
no se pueden emitir porque `mintCa` siempre autofirma.

Y hay un detalle que muerde: `mintCa` emite `BasicConstraints(CA:TRUE, pathLen:
0)`, y `pathLen 0` **prohíbe cualquier CA por debajo**. Comprobado con OpenSSL
sobre una jerarquía de tres niveles: `error 25 at 2 depth: path length
constraint exceeded`. Una raíz destinada a emitir sub-CAs tiene que salir con
`pathLen: 1`, y eso **se decide al crearla**: cambiarlo después es reemitir el
ancla, o sea invalidar todo lo que cuelga de ella.

Para una raíz autofirmada no hay nada que hacer: su retirada es la de la §1,
desaparecer de la lista (LoTE) o pasar a `deprecated` (AV TL). Por eso esto
queda como opción —útil para montar el caso "la wallet acepta una cadena cuya
intermedia está revocada"— y no como parte de la regla.

### 3.7 Lo ya emitido no lleva `CDP`: hay que reemitirlo

No se le puede añadir sin reemitirlo, porque cambiaría la firma. Mismo aviso
que con las listas: *esto no publica solo*. La consola debería listar qué
certificados vivos están **fuera de cobertura**, que es una pregunta que sólo
se puede contestar mirando la extensión de cada uno.

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

- `createCrl(store, { id, issuerKey, url, validityDays })` — **la llama
  `mintKey` al emitir cualquier CA**, no el operador. Que exista es parte de
  ser una CA (§3.1); dejarlo como paso manual reintroduce por la puerta de
  atrás la CA sin revocación que la regla quiere eliminar. A mano sólo para una
  CA importada con su clave.
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

**Estado del marco** (`apps/console/readiness.mjs`): la pantalla de estado ya
contesta "qué le falta a este despliegue". Con esta regla gana dos preguntas
más, que son las que hacen que "todas las CAs" no dependa de que alguien se
acuerde: **¿hay alguna CA sin CRL publicada?** y **¿hay certificados vivos sin
`CDP`?** (§3.7). Las dos se contestan recorriendo el almacén, no un checklist.

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

### 6.1 Y las listas **no** lo declaran

Tentación evidente: si cada CA ofrece revocación, publicarlo en la lista. Los
anexos de TS 119 602 definen para cada tipo de lista un segundo tipo de
servicio, `…/Revocation`, y la cláusula 6.6.7 da el sitio de la URI (el
`ServiceSupplyPoint`). La conclusión, sin embargo, es que **no hay que declarar
ninguno** — y el porqué obliga a leer con cuidado de qué habla ese servicio.

**El eje es lo que la entidad EMITE, no qué certificado suyo se publica.** Los
cinco anexos usan la misma fórmula: *«a service providing validity status
information on [lo que emite la entidad]»*. Y la identidad digital del servicio
(6.6.3) es, también en los cinco, el certificado que verifica la firma del
proveedor **sobre lo que emite**:

| Anexo | La entidad emite | Su `…/Revocation` informaría del estado de | Qué certificado suyo va en la lista |
|---|---|---|---|
| D — PID providers | datos de identidad (PID) | los PID | la **hoja** (Document Signer) |
| E — Wallet providers | wallet units | las wallet units | la **hoja** |
| F — WRPAC providers | access certificates (X.509) | los access certificates | la **CA emisora** |
| G — WRPRC providers | registration certificates (JWT) | los WRPRC | la **hoja** firmante |
| H — PubEAA | atestaciones de atributos | las atestaciones | la **hoja** firmante |

Que en el anexo F lo publicado sea la CA es **consecuencia** de lo que esa
entidad emite —para verificar la firma *sobre* un access certificate hace falta
el certificado de quien lo firmó, que es la CA—, no la causa de que exista el
servicio de revocación. El servicio existe igual en los cinco anexos, publiquen
CA o publiquen hoja.

**Corolario, y es el que contesta la pregunta de fondo:** el estado del
*propio* certificado que está en la lista **nunca** se expresa con un servicio
`…/Revocation`, sea CA o sea hoja. Ese estado lo dice la lista misma — quitando
la entrada (anexos D–G), con `withdrawn` (anexo H) o con `deprecated` (AV TL).
Un `…/Revocation` que apuntara a "la CRL donde se revoca esta ancla" estaría
usando el campo para otra cosa que la que la norma le da.

**Y aun así, declararlo no aporta.** Los anexos dicen *may be used*, y en los
dos casos que nos tocan el estado ya es descubrible desde el propio artefacto,
firmado por quien corresponde:

- **WRPRC**: el `status.status_list = { uri, idx }` viaja **dentro del
  certificado** (TS 119 475, REV-6.2.6.2-03). Quien tiene el WRPRC ya sabe
  dónde mirar y en qué posición; quien sólo mira la lista no tiene ningún
  WRPRC que comprobar. **No se declara.**
- **WRPAC**: exactamente lo mismo un escalón más abajo — el `CDP` viaja dentro
  del access certificate, firmado por la CA. **Tampoco se declara.**

La regla que queda es corta: *el servicio de estado se declara en la lista
cuando NO es descubrible desde el artefacto*. Hoy no se da ese caso. Se daría
en dos escenarios, ninguno de los cuales montamos: un **status issuer
delegado** (la §1 del borrador de Token Status List admite *«an entity that has
been authorized by the Issuer»*, con la delegación expresada por el EKU
`id-kp-oauthStatusSigning`) y una **CRL indirecta**, firmada por una clave
distinta de la CA emisora. En los dos, la lista sería el único sitio donde
consta que ese tercero está autorizado — y en los dos, el certificado que
habría que publicar en el servicio de revocación es el **del tercero**, no el
de la entidad. Las CRLs indirectas están fuera de alcance (§10).

Con lo cual `buildLote` sigue emitiendo **sólo el servicio de emisión**, que es
lo que ya hace, y por el motivo que ya tiene escrito en `packages/lote`. Esta
sección existe para que no se vuelva a proponer.

> **Dos erratas de la norma, de paso.** El anexo G define su servicio de
> revocación como *«validity status information on wallet relying party
> **access** certificates»* — copiado del anexo F; debería decir *registration*,
> y la fila de identidad digital justo debajo sí dice "registration
> certificates". El anexo H arrastra la misma frase, donde debería hablar de
> atestaciones de atributos. Es la tercera errata que nos encontramos en este
> documento, después del `WRPRCrovidersList` sin la P que el repo ya reproduce
> tal cual.

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

El reparto **no** es por CAs. La maquinaria es genérica —lo único que cambia
entre una CRL y otra es qué clave la firma—, así que hacerla para la Access CA
y luego "extenderla" a las demás sería trabajo inventado, y por el camino
dejaría un despliegue con unas CAs que revocan y otras que no. Las fases son
por **capas**, y la primera ya deja a todas las CAs del marco ofreciendo
revocación.

| Fase | Qué | Por qué | Esfuerzo |
|---|---|---|---|
| **F1** | La maquinaria por CA: documento `x509-crl` creado por `mintKey`, `revokeCert` / `buildCrl` / `checkRevoked`, `CDP` impuesto por la CA en `mintLeaf` / `mintRoleSigner` / `mintWrpac`, ruta en el publisher, comandos de CLI y sección en la consola. Tests unitarios, e2e y contraste con OpenSSL | Es la regla de la §0, entera. Vale igual para la Access CA, para las tres IACA y para cualquier CA que se cree mañana, porque nada de esto es específico de un rol | ~1 jornada |
| **F2** | Reemitir el material vivo para que salga con `CDP`, y la pregunta *"¿qué hay fuera de cobertura?"* en la pantalla de estado | Sin esto, F1 cubre lo que se emita a partir de ahora y deja el pasado invisible (§3.7) | ~2 h |
| **F3** | Estados de servicio: `deprecated` en la AV TL y `withdrawn` en `pubeaa-lab`, preservando `status` en `setProviders` (+ `ServiceHistory` en el XML) | Cierra la revocación de anclas en las dos listas que la expresan con un estado en vez de con una baja | ~2 h |
| **F4** | Los casos torcidos de la §7 como material de laboratorio | Es donde está el valor de medida: distinguir "implementa CRL" de "comprueba revocación" | ~½ jornada |
| **F5** (opcional) | Sub-CAs: `mint-ca --issuer` y `--path-len`, para poder revocar una CA entera (§3.6) | Sólo hace falta para el escenario "la wallet acepta una cadena con la intermedia revocada". No es parte de la regla | ~3 h |

No hay fase para *declarar el servicio de revocación en las listas*: no se
declara (§6.1). El estado ya viaja dentro de cada artefacto —el `CDP` en el
access certificate, el `{uri, idx}` en el WRPRC— y la lista no es el sitio
donde se dice el estado de lo que un proveedor emite.

Dentro de F1, el orden natural es Access CA primero **como banco de pruebas del
código**, no como alcance: es la que tiene consumidor externo real (la wallet
comprueba el access certificate) y la que da el primer resultado medible. Pero
F1 no se da por hecha hasta que las CAs del despliegue —Access CA e IACAs—
publican su CRL.

## 10. Fuera de alcance, y por qué

- **OCSP.** Es un servicio en línea con su responder, su certificado, su perfil
  y su disponibilidad. La norma pide un servicio de estado, no OCSP en
  concreto; la CRL es un fichero firmado estático y encaja con lo que este
  laboratorio ya es: un publisher de solo lectura que sirve artefactos
  inmutables.
- **Delta CRLs e `IssuingDistributionPoint`.** Optimización para CRLs enormes.
  La nuestra pesa 294 bytes.
- **CRLs indirectas** (firmadas por una clave distinta de la CA emisora). Es
  uno de los dos únicos escenarios en los que la lista tendría que declarar el
  servicio de revocación (§6.1); montarlo para poder declararlo sería la cola
  moviendo al perro.
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
