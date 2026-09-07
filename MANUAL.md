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

## 4. El orden de las cosas

Nada de esto es opcional ni reordenable. Cada paso necesita el anterior:

```
firmante de listas (TLSO)
   ├── AV Trusted List (XML)  ← necesita además un PAAP con su certificado
   ├── LoTE de PID / wallet providers / WRPAC / WRPRC
   ├── status list de revocación
   └── firma los WRPRC
CA de acceso
   └── access certificate (WRPAC)  ← necesita el registro de la RP
registro de la RP
   ├── access certificate   (uno por servicio)
   └── registration certificate (uno por finalidad)
```

El **dashboard** de la consola (`/`) es exactamente ese grafo: cada tarjeta dice
si algo se puede emitir ya o qué falta. Si no sabes cuál es el siguiente paso,
la respuesta está ahí.

---

## 5. Paso a paso

### 5.1 Firmante de listas

Es el primer requisito de todo: sin él no se firma ninguna lista y, por tanto,
no se emite ningún WRPRC. Lleva el perfil de la **cláusula 5.7.1 de
TS 119 612**: `CA=false`, `KeyUsage` acotado a `digitalSignature`/
`nonRepudiation`, EKU `id-tsl-kp-tslSigning` (`0.4.0.2231.3.0`) y un subject
cuyos `C` y `O` salen del esquema que va a firmar.

> Consola: **Claves → Firmante de listas (TLSO)**, eligiendo el esquema.

```bash
node apps/cli/index.mjs mint-tl-signer tl-signer av-lab
```

Que el `C` no coincida con el territorio del esquema es un **aviso**, no un
error: la AV TL de producción hace exactamente eso (`C=LU` con territorio `EU`).

### 5.2 Las listas

`state/` trae siete documentos sembrados: un registro de relying party de
ejemplo (`espuni-rp`, §5.4) y seis de listas:

| Documento | Formato | Qué contiene |
|---|---|---|
| `av-lab` | ETSI TS 119 612 (XML + XAdES) | proveedores de atestación de edad (PAAP) |
| `pid-lab` | ETSI TS 119 602 (LoTE, JSON en JWS) | PID providers |
| `wallet-lab` | LoTE | wallet providers |
| `wrpac-lab` | LoTE | prestadores de certificados de acceso |
| `wrprc-lab` | LoTE | prestadores de certificados de registro |
| `status-wrprc` | IETF Token Status List | revocación de los WRPRC (1024 posiciones) |

Una lista se emite en dos tiempos: **poblarla** y **firmarla**.

```bash
# la AV TL lleva PAAPs, con el Estado miembro que los notifica
node apps/cli/index.mjs mint-ca av-issuer "CN=AV Issuer, O=Lab, C=ES"
node apps/cli/index.mjs add-provider av-lab av-issuer "Lab AV Issuer" ES
node apps/cli/index.mjs build-list av-lab tl-signer

# las LoTE llevan entidades, con clave de emisión y opcionalmente de revocación
node apps/cli/index.mjs mint-ca pid-issuer "CN=PID Issuer, O=Lab, C=ES"
node apps/cli/index.mjs add-entity pid-lab pid-issuer "Lab PID Provider"
node apps/cli/index.mjs build-lote pid-lab tl-signer
```

> Consola: **Listas** para poblar (`Editar`) y el dashboard para firmar.

Cada emisión **se verifica antes de guardarse**: la AV TL contra el Anexo B de
TS 119 612 y el perfil de la Comisión, y se relee con `@owf/eudi-tl` —la misma
librería que usa el consumidor— antes de darla por buena. Una lista que no
valida no llega al almacén, así que el publisher no puede servirla.

El XML es el caro: XAdES *enveloped*, canonicalización **exclusiva**,
`SigningCertificateV2`. Los valores por defecto de la librería de firma están
mal en los cuatro puntos, así que se fijan a mano.

### 5.3 CA de acceso

```bash
node apps/cli/index.mjs mint-ca access-ca "CN=Lab Access CA, O=Lab, C=ES"
```

> Consola: **Claves → CA / hoja**.

En producción esta CA sería un prestador acreditado bajo TS 119 411-8. Aquí es
una raíz que te has creado tú; para que una wallet la acepte, tiene que estar
en la LoTE `wrpac-lab` y la wallet tiene que confiar en esa lista.

### 5.4 Dar de alta una relying party

> Consola: formulario al final de **Relying parties**.

```bash
node apps/cli/index.mjs new-rp bodegas-valle "Bodegas del Valle S.A." A87654321 ES status-wrprc
```

Crea un esqueleto **que ya valida** contra TS5/TS6, con un servicio y una
finalidad de ejemplo (AV, `age_over_18` sobre `eu.europa.ec.av.1`), y **reserva
una posición libre** en la lista de revocación.

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

### 5.5 Access certificate (WRPAC)

Uno **por servicio**.

> Consola: **Relying parties → \<la RP\> → Emitir access certificate**.

```bash
node apps/cli/index.mjs mint-wrpac access-ca bodegas-valle svc-1
```

Sale con la política `NCP-l-eudiwrp` (`0.4.0.194118.1.2`) y el
`organizationIdentifier` derivado del registro. Sus atributos **salen del
registro**, no de argumentos sueltos: GEN-6.6.1-10 de TS 119 411-8 lo exige así.

### 5.6 Registration certificate (WRPRC)

Uno **por finalidad**. Es un JWS compacto (`typ: rc-wrp+jwt`), no un X.509, y lo
firma un firmante de listas.

> Consola: **Relying parties → \<la RP\>**, botón `Emitir` de cada finalidad.

```bash
node apps/cli/index.mjs issue-wrprc bodegas-valle svc-1 use-1 tl-signer
```

Se emite en la edición **v1.2.1** de TS 119 475 y se relee para confirmar qué
edición detecta un consumidor. Si el registro declara campos que la edición
vigente no transporta, se avisa al emitir en vez de perderlos en silencio.

### 5.7 Publicar

Firmar **no publica**: deja el artefacto en el almacén. El publisher sirve lo
último emitido de cada documento, en **la ruta que ese documento declara** en su
campo `url`.

```bash
curl -s https://<publisher>/                      # índice de lo publicado
curl -sI https://<publisher>/lists/av-lab.xml     # Content-Type correcto
curl -s -X POST https://<publisher>/lists/av-lab.xml   # 405, nunca escribe
```

⚠ **La URL viaja dentro de lo firmado**: el `sub` de la status list, el puntero
de la AV TL a sí misma, el `status.status_list.uri` de cada WRPRC. Si vas a
servir en un dominio distinto de `trust-lab.espuni.com`, **edita el campo `url`
de cada documento antes de emitir nada**. Cambiarlo después no arregla lo ya
firmado: hay que reemitir.

El índice `/` muestra, por documento, `path` (donde se sirve), `canonical`
(el atajo `/tipo/id`, que además admite versiones históricas) y `declaredUrl`.
Si `path` y `declaredUrl` no coinciden, algo está mal.

### 5.8 Revocar

```bash
node apps/cli/index.mjs status-check status-wrprc 0 tl-signer   # → valid
node apps/cli/index.mjs status-set   status-wrprc 0 invalid "finalidad retirada"
node apps/cli/index.mjs status-build status-wrprc tl-signer
node apps/cli/index.mjs status-check status-wrprc 0 tl-signer   # → invalid
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

---

## 8. Referencia

### Pantallas de la consola

| Ruta | Qué hay |
|---|---|
| `/` | dashboard: el grafo de dependencias, qué se puede emitir y qué falta |
| `/lists` | los documentos de lista, su estado de publicación y el editor |
| `/keys` | pares clave+certificado: qué es cada uno, caducidad y descargas |
| `/rps` | relying parties, alta de nuevas |
| `/rps/:id` | servicios, finalidades, emisión y descarga de sus certificados |
| `/status` | posiciones de revocación |
| `/docs/:id` | editor JSON de cualquier documento, con validación al guardar |

### Comandos del CLI

```
mint-ca <nombre> "<DN>"                             CA raíz autofirmada
mint-leaf <ca> <nombre> "<DN>"                      hoja firmada por esa CA
mint-tl-signer <nombre> <esquema>                   firmante de listas (5.7.1)
mint-wrpac <ca> <registro> <servicio> [nombre]      access certificate

new-rp <id> "<razón social>" <valor-id> [país] [lista-revocación] [tipo-id]
issue-wrprc <registro> <servicio> <finalidad> <firmante>

add-provider <estado> <clave> "<nombre>" <CC>       PAAP en la AV TL
add-entity <estado> <clave-emisión> "<nombre>" [clave-revocación]
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

**Dos posiciones de revocación compartidas revocan dos RP de golpe.** El alta
reserva una posición libre precisamente para que eso se detecte cuando no cuesta
nada, y no cuando ya hay material firmado apuntando a ella.
