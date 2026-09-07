# Manual de operación

Cómo se usa trust-lab: montar un marco de confianza EUDI completo —listas,
certificados de acceso y certificados de registro— y servirlo para que una
wallet lo consuma.

Este manual es **operativo**. El *por qué* de cada decisión está en
[`README.md`](README.md); el despliegue, en [`DEPLOY.md`](DEPLOY.md).

---

## 1. Qué es esto y qué no es

Es una **fábrica de material de confianza para pruebas**. Emite lo que en
producción emitirían un Estado miembro y sus prestadores acreditados —que hoy
no existen para acceso ni para registro— y lo publica en las mismas formas y
formatos que las listas reales de la Comisión.

Lo que produce es **conforme en formato, no en autoridad**. Un verificador que
confíe en estas listas está confiando en una raíz que has creado tú. Sirve para
lo que se hizo: comprobar que una wallet valida bien la cadena, que rechaza lo
que debe rechazar y que el marco encaja de punta a punta antes de que existan
las autoridades de verdad.

**Nunca** apuntes un despliegue de producción a estas listas.

### Los tres entornos

| Entorno | De dónde salen las listas |
|---|---|
| **Pruebas** | este laboratorio |
| **Preproducción** | listas de *acceptance* de la Comisión |
| **Producción** | listas de producción de la Comisión |

Solo el primero es cosa tuya. Los otros dos son consumo: se apunta la wallet a
la URL de la Comisión y se pinea su firmante.

---

## 2. Las dos superficies

Son **dos servicios separados**, y la separación es la propiedad de seguridad
principal del diseño:

| | **Consola** | **Publisher** |
|---|---|---|
| Qué hace | crea CAs, firma listas, emite certificados | sirve bytes ya firmados |
| Escribe | sí | **nunca** (405 en cualquier método que no sea GET/HEAD) |
| Autenticación | contraseña obligatoria para arrancar | ninguna: es público |
| Descifra claves | sí (`TRUST_LAB_KEY`) | **no puede** — ni pide la variable |
| Dominio | el generado por Railway, sin publicar | el dominio público |

Un tercer frontal, el **CLI** (`apps/cli`), hace lo mismo que la consola desde
la línea de comandos. Las operaciones viven en un solo sitio
(`packages/ops`) y los dos frontales las comparten, así que no divergen.

---

## 3. Puesta en marcha

### En Railway

Dos servicios sobre el mismo repositorio y **la misma base de datos**:

| Variable | Consola | Publisher |
|---|---|---|
| `TRUST_LAB_APP` | `console` | `publisher` (o sin definir) |
| `DATABASE_URL` | la del plugin de Postgres | **la misma** |
| `TRUST_LAB_KEY` | 32 bytes en hex o base64 | — |
| `CONSOLE_PASSWORD` | obligatoria | — |
| `CONSOLE_SECRET` | opcional | — |

`TRUST_LAB_APP=console` es fácil de olvidar: sin ella el servicio arranca el
publisher y verás su JSON donde esperabas la consola. Desde `d0474a1` avisa por
log cuando detecta esa confusión.

**Postgres no es opcional en Railway.** El disco del contenedor es efímero y no
se comparte entre servicios: con el almacén de fichero, la consola escribiría en
un disco que el publisher no ve y todo se perdería en el siguiente despliegue.
El arranque falla explícitamente si detecta Railway sin `DATABASE_URL`, en vez
de degradar en silencio.

La primera vez que arranca contra una base vacía, siembra los seis documentos
de `state/`.

### En local

```bash
npm install
export TRUST_LAB_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

node apps/cli/index.mjs <comando>          # CLI, almacén de fichero
CONSOLE_PASSWORD=lab node apps/console/index.mjs   # consola en :8081
node apps/publisher/index.mjs              # publisher en :8080
```

El almacén se elige por entorno, en este orden: `TRUST_LAB_PGLITE` (Postgres en
WASM, sin servidor — es el que usan los tests) → `DATABASE_URL` → fichero
(`state/`, `out/`).

---

## 4. El marco completo, de un vistazo

Un marco de confianza son **cinco listas y tres jerarquías de certificados**, y
todo encaja por el mismo mecanismo: *un artefacto vale si su cadena termina en
un ancla que publica la lista que le corresponde*. Nada más. No hay OID mágico
ni perfil que sustituya a eso.

| Quién firma qué | Certificado | Cuelga de | Su ancla se publica en |
|---|---|---|---|
| las cinco listas | firmante de listas (TLSO) | nadie (autofirmado) | se **pinea** en el consumidor |
| las atestaciones de edad | Document Signer de AV | IACA de AV | `av-lab` (AV Trusted List) |
| el PID | Document Signer del PID | CA del PID provider | `pid-lab` |
| la Wallet Instance Attestation | firmante de WIA | CA del wallet provider | `wallet-lab` |
| las Key Attestation | firmante de KA | CA del wallet provider | `wallet-lab` |
| — (los emite) | access certificate de la RP | CA de acceso | `wrpac-lab` |
| los registration certificates | firmante de WRPRC | CA del proveedor de WRPRC | `wrprc-lab` |
| — (se revocan) | los WRPRC | — | `status-wrprc` |

El **firmante de listas es la excepción**: no está en ninguna lista, porque es
quien las firma. Su certificado se pinea en el otro extremo, y eso es lo que
convierte a las listas en evidencia. Es también el único ancla del laboratorio
que hay que instalar a mano en la wallet.

El orden se deduce de la tabla y no es reordenable:

```
firmante de listas (TLSO)  ──────── firma las cinco listas
IACA de AV ──→ DS de AV ───────────→ av-lab
CA del PID ──→ DS del PID ─────────→ pid-lab
CA del wallet ──→ WIA · KA ────────→ wallet-lab
CA de acceso ──────────────────────→ wrpac-lab
   └── access certificate (uno por servicio de la RP)
CA de WRPRC ──→ firmante WRPRC ────→ wrprc-lab
   └── registration certificate (uno por finalidad)
status list ───────────────────────→ revoca los WRPRC
```

El **dashboard** de la consola (`/`) es ese grafo calculado sobre el almacén:
cada tarjeta dice si algo se puede emitir ya o qué falta. Si no sabes cuál es el
siguiente paso, la respuesta está ahí.

> ⚠ **Las listas vienen sembradas con un proveedor de ejemplo cuya clave privada
> no existe.** Son anclas que nadie puede usar. Un despliegue nuevo tiene que
> quitarlas y poner las suyas (`remove-provider`, §5.3); si no, las listas
> declaran confianza en material que no puedes emitir.

---

## 5. Desplegar el marco completo

Esto es el guion entero. Ejecutado tal cual, deja un marco de confianza
funcionando: cinco listas firmadas y publicadas, y una relying party con sus dos
certificados.

Los ejemplos van con el CLI porque se leen mejor en orden; **todo tiene su
equivalente en la consola** y se indica en cada paso.

### 5.1 Firmante de listas (TLSO)

Primer requisito de todo: sin él no se firma ninguna lista. Lleva el perfil de
la **cláusula 5.7.1 de TS 119 612** — `CA=false`, `KeyUsage` acotado a
`digitalSignature`/`nonRepudiation`, EKU `id-tsl-kp-tslSigning`
(`0.4.0.2231.3.0`), y un subject cuyos `C` y `O` salen del esquema.

```bash
node apps/cli/index.mjs mint-tl-signer tl-signer av-lab
```

> Consola: **Claves → Firmante de listas (TLSO)**.

Las cinco listas del laboratorio declaran el mismo *scheme operator*
(`espuni Trust Lab`, territorio `EU`), así que **uno sirve para todas**. Si el
`C` no coincide con el territorio es un **aviso**, no un error: la AV TL de
producción hace exactamente eso (`C=LU` con territorio `EU`).

### 5.2 Las tres jerarquías de emisión

Una CA por dominio, y debajo el certificado que firma de verdad. La CA es lo que
va a la lista; la hoja es lo que firma.

```bash
T="node apps/cli/index.mjs"

# AV — la Trusted List lleva el DS, no la IACA
$T mint-ca     av-iaca "C=ES, O=Lab AV Attestation Provider, CN=Lab AV IACA"
$T mint-signer av-iaca av-ds mdoc-ds "C=ES, O=Lab AV Attestation Provider, CN=Lab AV DS 01"

# PID
$T mint-ca     pid-ca "C=ES, O=Lab PID Provider, CN=Lab PID Issuing CA"
$T mint-signer pid-ca pid-ds pid-ds "C=ES, O=Lab PID Provider, CN=Lab PID DS 01"

# Wallet provider — WIA y Key Attestation
$T mint-ca     wallet-ca "C=ES, O=Lab Wallet Provider, CN=Lab Wallet Provider CA"
$T mint-signer wallet-ca wia-signer wia "C=ES, O=Lab Wallet Provider, CN=Lab WIA Signer 01"
$T mint-signer wallet-ca ka-signer key-attestation "C=ES, O=Lab Wallet Provider, CN=Lab KA Signer 01"

# Acceso y registro de relying parties
$T mint-ca     wrpac-ca "C=ES, O=Lab Access CA, CN=Lab WRPAC Issuing CA"
$T mint-ca     wrprc-ca "C=ES, O=Lab RC Provider, CN=Lab WRPRC Issuing CA"
$T mint-signer wrprc-ca wrprc-signer wrprc "C=ES, O=Lab RC Provider, CN=Lab WRPRC Signer 01"
```

> Consola: **Claves → CA / hoja** para las CAs, **Claves → Firmante de
> credenciales o atestaciones** para los cinco firmantes.

Los cinco roles de `mint-signer`:

| Rol | Qué firma | Perfil |
|---|---|---|
| `mdoc-ds` | atestaciones de edad (MSO) | hoja + EKU `1.0.18013.5.1.2` |
| `pid-ds` | el PID | igual; cambia de quién cuelga |
| `wrprc` | registration certificates | hoja, sin EKU |
| `wia` | Wallet Instance Attestation | hoja, sin EKU |
| `key-attestation` | Key Attestation | hoja, sin EKU |

**Por qué unos llevan EKU y otros no.** El de mdoc es el Document Signer de
ISO/IEC 18013-5, que sí lo define. En los otros tres, la confianza la establece
el **encadenamiento con el ancla publicada**, no un OID: TS 119 475 no le pide
ningún EKU al firmante de un WRPRC — el `id-tsl-kp-tslSigning` es de TS 119 612
y solo aplica a quien firma listas. Aquí no se inventan OIDs: un OID que la
norma no exige no añade confianza y sí puede hacer que un validador estricto
rechace el certificado.

> Antes de esto solo había dos perfiles de hoja con nombre —el firmante de
> listas y el access certificate— y en la práctica los WRPRC acababan firmados
> con el TLSO, que **no encadena** con la CA declarada en `wrprc-lab`. Una
> cadena que no llega a la lista no es una cadena.

### 5.3 Poblar las listas

Cada lista se puebla con el **ancla** de su dominio. Primero hay que quitar el
proveedor de ejemplo que viene sembrado, porque su clave privada no existe:

```bash
for L in av-lab pid-lab wallet-lab wrpac-lab wrprc-lab; do
  $T remove-provider $L 0
done

$T add-provider av-lab     av-ds         "Lab AV Attestation Provider" ES
$T add-entity   pid-lab    pid-ds        "Lab PID Provider"
$T add-entity   wallet-lab wia-signer    "Lab Wallet Provider"
$T add-entity   wrpac-lab  wrpac-ca      "Lab Access Certificate Provider"
$T add-entity   wrprc-lab  wrprc-signer  "Lab Registration Certificate Provider"
```

> Consola: **Listas → Editar** (el registro se edita como documento JSON).

Los dos comandos no son intercambiables, y toman cosas distintas:

- **`add-provider`** puebla la **AV Trusted List** (XML) y guarda el certificado
  que le nombras, tal cual. Por eso se le pasa el **DS**: es lo que lleva la AV
  TL real. Necesita además el código del Estado miembro que notifica al PAAP.
- **`add-entity`** puebla una **LoTE** (JSON en JWS) y guarda el **ancla de la
  cadena** —la raíz, no la hoja—, así que da igual si le nombras la CA o algo
  que cuelgue de ella. Admite una segunda clave para el servicio de revocación.

### 5.4 Firmar y publicar las listas

```bash
$T build-list av-lab tl-signer                      # XML + XAdES
for L in pid-lab wallet-lab wrpac-lab wrprc-lab; do
  $T build-lote $L tl-signer                        # JSON en JWS
done
$T status-build status-wrprc tl-signer              # lista de revocación
```

> Consola: el dashboard, botón de cada tarjeta.

Cada emisión **se verifica antes de guardarse**: la AV TL contra el Anexo B de
TS 119 612 y el perfil de la Comisión, y se relee con `@owf/eudi-tl` —la misma
librería que usa el consumidor— antes de darla por buena. Una lista que no
valida no llega al almacén, así que el publisher no puede servirla.

El XML es el caro: XAdES *enveloped*, canonicalización **exclusiva**,
`SigningCertificateV2`. Los valores por defecto de la librería de firma están
mal en los cuatro puntos, así que se fijan a mano.

**Firmar no publica**: deja el artefacto en el almacén. El publisher sirve lo
último emitido de cada documento, en **la ruta que ese documento declara**.

```bash
curl -s https://<publisher>/                      # índice de lo publicado
curl -sI https://<publisher>/lists/av-lab.xml     # Content-Type correcto
curl -s -X POST https://<publisher>/lists/av-lab.xml   # 405: nunca escribe
```

⚠ **La URL viaja dentro de lo firmado**: el `sub` de la status list, el puntero
de la AV TL a sí misma, el `status.status_list.uri` de cada WRPRC. Si vas a
servir en un dominio distinto de `trust-lab.espuni.com`, **edita el campo `url`
de cada documento antes de emitir nada**. Cambiarlo después no arregla lo ya
firmado: hay que reemitir.

### 5.5 Dar de alta una relying party

> Consola: formulario al final de **Relying parties**.

```bash
$T new-rp bodegas "Bodegas del Valle S.A." A87654321 ES status-wrprc
```

Crea un esqueleto **que ya valida** contra TS5/TS6, con un servicio y una
finalidad de ejemplo (AV, `age_over_18` sobre `eu.europa.ec.av.1`), y **reserva
una posición libre** en la lista de revocación. Reservarla en el alta y no al
emitir el certificado es deliberado: dos altas que eligen la misma posición se
detectan cuando no cuesta nada, y no cuando ya hay material firmado apuntando a
una posición compartida — que es como se revocan dos RP de golpe.

Lo que queda por rellenar va marcado como `PENDIENTE — …`. Se edita desde
`Editar el registro`, como documento JSON y no como formulario: el modelo de TS5
tiene servicios, finalidades, credenciales y claims anidados, y cuarenta campos
en un formulario serían más lentos de usar y más fáciles de romper que el JSON
con validación al guardar.

La jerarquía manda, y tiene un nivel que un modelo improvisado se salta:

```
WalletRelyingParty          ← la entidad legal registrada
  └── services[]            ← un access certificate por cada uno
        └── intendedUses[]  ← un registration certificate por cada uno
              └── credentials[] → claims[]
```

El identificador semántico (`VATES-B12345678`) **se deriva** del identificador
tipado del registro; no se escribe a mano en ninguno de los dos certificados.

### 5.6 Los dos certificados de la relying party

Uno de acceso **por servicio**, uno de registro **por finalidad**:

```bash
$T mint-wrpac  wrpac-ca bodegas svc-1              # access certificate
$T issue-wrprc bodegas svc-1 use-1 wrprc-signer    # registration certificate
```

> Consola: **Relying parties → \<la RP\>**.

El access certificate sale con la política `NCP-l-eudiwrp`
(`0.4.0.194118.1.2`) y el `organizationIdentifier` derivado del registro. Sus
atributos **salen del registro**, no de argumentos sueltos: GEN-6.6.1-10 de
TS 119 411-8 lo exige así.

El WRPRC es un JWS compacto (`typ: rc-wrp+jwt`), no un X.509. Se emite en la
edición **v1.2.1** de TS 119 475 y se relee para confirmar qué edición detecta
un consumidor. Si el registro declara campos que la edición vigente no
transporta, se avisa al emitir en vez de perderlos en silencio.

**Fíjate en quién firma cada uno**: el access certificate lo emite `wrpac-ca`,
que es el ancla de `wrpac-lab`; el WRPRC lo firma `wrprc-signer`, que cuelga de
`wrprc-ca`, que es el ancla de `wrprc-lab`. Ese emparejamiento es todo el
mecanismo. Firmar con la clave equivocada produce artefactos que validan
criptográficamente y no encadenan con nada.

### 5.7 Comprobar que el marco cierra

La pregunta que importa no es «¿se emitió?», sino «¿termina la cadena en el
ancla publicada?». Se responde comparando huellas:

```bash
$T export wrprc bodegas-svc-1-use-1 /tmp/w.jwt
$T export-key bodegas-svc-1-access chain /tmp/ac.pem
```

- La **última entrada del `x5c`** del WRPRC tiene que ser, byte a byte, el
  `issuanceCertPem` del proveedor en `wrprc-lab`.
- El **último certificado de la cadena** del access certificate tiene que ser el
  de `wrpac-lab`.

Si no coinciden, la wallet rechazará el artefacto aunque la firma sea válida —
y ese es el fallo que este laboratorio existe para provocar y detectar.

### 5.8 Revocar

```bash
$T status-check status-wrprc 0 tl-signer   # → valid
$T status-set   status-wrprc 0 invalid "finalidad retirada"
$T status-build status-wrprc tl-signer
$T status-check status-wrprc 0 tl-signer   # → invalid
```

> Consola: **Revocación**.

Cambiar una posición **no publica nada**: hay que reemitir la lista para que el
cambio salga. La lista se reserva entera de golpe (1024 posiciones) en vez de
crecer con cada revocación, porque una lista que crece filtra cuántos
certificados hay vivos.

---

## 6. Descargar el material

Los certificados se emiten aquí pero se **usan fuera**: el access certificate lo
instala la RP en su despliegue y el WRPRC viaja dentro de la petición OID4VP. La
puerta de salida está **solo en la consola**; el publisher no tiene ninguna de
estas rutas.

| Forma | Qué lleva | ¿Secreta? |
|---|---|---|
| `chain` | el certificado y su cadena | **no** — es lo que se pinea en el otro extremo |
| `bundle` | clave privada + cadena | sí |
| `key` | solo la clave privada | sí |
| `jwk` | JWK privada con `x5c` | sí |

```bash
node apps/cli/index.mjs export-key bodegas-valle-svc-1-access chain  out/
node apps/cli/index.mjs export-key bodegas-valle-svc-1-access bundle out/   # 0600
node apps/cli/index.mjs export     wrprc bodegas-valle-svc-1-use-1   out/
```

> Consola: enlaces en **Claves** y en **Relying parties → \<la RP\>**.

Las descargas con clave privada se marcan con 🔑, se escriben `0600` y dejan
línea en el log del servicio.

---

## 7. Apuntar una wallet al laboratorio

Es para lo que existe todo lo anterior. Para que una wallet valide contra este
marco necesita, según lo que esté comprobando:

1. **La AV Trusted List** — URL de `av-lab` y el **certificado del firmante**
   pineado. Se saca con `export-key <firmante> chain`.
2. **La LoTE de wallet o PID providers** — igual, con su firmante.
3. **La LoTE de WRPAC providers** — para que acepte tu CA de acceso.
4. **El access certificate del RP** — instalado en el verificador que hace la
   petición.
5. **El registration certificate** — el JWS que el verificador presenta en la
   petición OID4VP.

Cada lista se pinea por su **firmante**, no por su URL: es lo que la convierte
en evidencia. Cambiar de firmante obliga a re-pinear en el otro extremo.

Como las cinco listas del laboratorio las firma el mismo TLSO, en la práctica
**solo hay un ancla que instalar a mano** en la wallet; todo lo demás lo
descubre siguiendo las listas.

---

## 8. Referencia

### Pantallas de la consola

| Ruta | Qué hay |
|---|---|
| `/` | dashboard: el grafo de dependencias, qué se puede emitir y qué falta |
| `/lists` | los documentos de lista, su estado de publicación y el editor |
| `/keys` | pares clave+certificado: qué es cada uno, caducidad y descargas; emisión de CAs, del firmante de listas y de los firmantes de credenciales |
| `/rps` | relying parties, alta de nuevas |
| `/rps/:id` | servicios, finalidades, emisión y descarga de sus certificados |
| `/status` | posiciones de revocación |
| `/docs/:id` | editor JSON de cualquier documento, con validación al guardar |

### Comandos del CLI

```
mint-ca <nombre> "<DN>"                             CA raíz autofirmada
mint-leaf <ca> <nombre> "<DN>"                      hoja genérica
mint-tl-signer <nombre> <esquema>                   firmante de listas (5.7.1)
mint-signer <ca> <nombre> <rol> "<DN>"              firmante de credenciales
      roles: mdoc-ds | pid-ds | wrprc | wia | key-attestation
mint-wrpac <ca> <registro> <servicio> [nombre]      access certificate

new-rp <id> "<razón social>" <valor-id> [país] [lista-revocación] [tipo-id]
issue-wrprc <registro> <servicio> <finalidad> <firmante>

add-provider <estado> <clave> "<nombre>" <CC>       PAAP en la AV TL (el DS)
add-entity <estado> <clave-emisión> "<nombre>" [clave-revocación]   ancla en una LoTE
remove-provider <estado> <índice|nombre>            quita una entrada
build-list <estado> <firmante>                      firma la AV TL (XML)
build-lote <estado> <firmante>                      firma una LoTE (JSON/JWS)

status-set <estado> <posición> <valid|invalid|suspended> ["motivo"]
status-build <estado> <firmante>
status-check <estado> <posición> <firmante>

export-key <nombre> [chain|bundle|key|jwk] [destino]
export <tipo> <id> [destino]                        tipo: wrprc|lists|lote|status
```

Donde pide un estado o un registro acepta tanto `av-lab` como
`state/av-lab.json`: lo que cuenta es el id.

### Variables de entorno

| Variable | Quién la usa | Para qué |
|---|---|---|
| `TRUST_LAB_APP` | arranque | `console` o `publisher` (default) |
| `CONSOLE_PASSWORD` | consola | **obligatoria**: sin ella no arranca |
| `CONSOLE_SECRET` | consola | firma de la cookie; sin ella, sesiones efímeras |
| `TRUST_LAB_KEY` | consola, CLI | cifra el material privado en reposo (AES-256-GCM) |
| `DATABASE_URL` | todos | Postgres; obligatoria en Railway |
| `TRUST_LAB_PGLITE` | tests, local | Postgres en WASM, sin servidor |
| `PORT` | servicios | puerto de escucha |
| `MAX_CACHE_SECONDS` | publisher | tope del `Cache-Control` derivado del `nextUpdate` |

`TRUST_LAB_KEY` falla **cerrado**: sin ella no se guarda ninguna clave en claro,
se rechaza la operación. Rotarla deja ilegible el material ya guardado.

---

## 9. Cosas que muerden

**El disco de Railway es efímero.** Si la consola arrancara con almacén de
fichero, cada despliegue se llevaría las claves y los artefactos. Por eso el
arranque falla si detecta Railway sin `DATABASE_URL`. Los dos servicios tienen
que apuntar a **la misma** base.

**Firmar no es publicar.** Un cambio en un documento no sale hasta que se
reemite la lista. Vale para revocaciones, para nuevos PAAP y para todo lo demás.

**`nextUpdate` vencido no es un aviso menor.** El procedimiento §4.1 de la
especificación de la AV TL manda devolver `FAILED` con una lista caducada, y un
consumidor que falle cerrado la rechazará. El dashboard marca las vencidas.

**Los identificadores de servicio no son únicos entre RPs.** TS5 no lo exige, y
todos los esqueletos nacen con `svc-1`/`use-1`. Los artefactos WRPRC llevan el
registro delante (`<registro>-<servicio>-<finalidad>`) justamente para que dos
RP no se pisen el certificado.

**El nombre de una clave no dice lo que es.** Lo pone quien la emite. El rol —CA,
firmante de listas, access certificate, hoja— sale de las extensiones del
certificado, y es lo que muestra la columna «Qué es» de `/keys`.

**Las listas sembradas traen anclas inservibles.** El proveedor de ejemplo de
cada lista tiene un certificado cuya clave privada no existe en ningún sitio. Si
no lo quitas (`remove-provider`), tus listas declaran confianza en material que
no puedes emitir, y lo que sí emitas no encadenará con nada.

**Firmar con la clave equivocada produce artefactos que no encadenan.** Un WRPRC
firmado con el TLSO valida criptográficamente y no llega a `wrprc-lab`, porque el
TLSO no cuelga de la CA que esa lista publica. La comprobación de §5.7 es la que
lo detecta; la firma correcta, por sí sola, no dice nada.

**Dos posiciones de revocación compartidas revocan dos RP de golpe.** El alta
reserva una posición libre precisamente para que eso se detecte cuando no cuesta
nada, y no cuando ya hay material firmado apuntando a ella.
