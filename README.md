# trust-lab

Fábrica de material de confianza para probar wallets EUDI: emite las listas y
los certificados que en producción emitirían un Estado miembro y sus
prestadores acreditados, en los mismos formatos que las listas reales de la
Comisión.

Empezó siendo solo un CLI que escupía artefactos firmados estáticos (la
«opción C» del diseño inicial). Hoy son además dos servicios —una **consola**
autenticada que emite y un **publisher** de solo lectura que sirve—, y los tres
frontales comparten las mismas operaciones.

```bash
node apps/cli/index.mjs mint-ca    tl-signer "C=ES, O=espuni Trust Lab, CN=Trust Lab Scheme Operator"
node apps/cli/index.mjs mint-ca    av-iaca   "C=ES, O=Lab AV Attestation Provider, CN=Lab AV IACA"
node apps/cli/index.mjs mint-leaf  av-iaca av-ds "C=ES, O=Lab AV Attestation Provider, CN=Lab AV DS 01"
node apps/cli/index.mjs add-provider av-lab av-ds "Lab AV Attestation Provider" ES
node apps/cli/index.mjs build-list av-lab tl-signer
```

Y una lista LoTE (JSON en un JWS) — aquí, la de proveedores de certificados de
acceso, que es la que ninguna herramienta existente sabía emitir:

```bash
node apps/cli/index.mjs mint-ca     wrpac-ca-1 "C=ES, O=Lab Access CA, CN=Lab WRPAC Issuing CA"
node apps/cli/index.mjs add-entity  wrpac-lab wrpac-ca-1 "Lab Access Certificate Provider"
node apps/cli/index.mjs build-lote  wrpac-lab tl-signer
```

```
perfil EUWRPACProvidersList · tipos de servicio .../SvcType/WRPAC/{Issuance,Revocation}
JWS verificado · nextUpdate 2026-10-07T13:18:07Z · 1 entidad(es)
```

La última orden emite `out/lists/av-lab.xml` **y la verifica con `@owf/eudi-tl`**,
que es la misma librería que usan EUDIPLO en el camino clásico y espuni en el
camino ZK. Si pasa aquí, la aceptan los dos.

> **Cómo se opera esto**: [`MANUAL.md`](MANUAL.md) — el recorrido completo,
> de la primera clave a la lista publicada. Este documento explica el *por qué*;
> el manual, el *cómo*.

## Los cuatro contratos (lo que hace barato migrar a un servicio)

1. **Los paquetes no tocan I/O.** `packages/*` recibe material y devuelve bytes.
   El único fichero con `fs` es `apps/cli/index.mjs`. También es el único que
   fija el motor global de `@peculiar/x509`.
2. **Toda firma pasa por `Signer`** (`sign(bytes)` + `certificateChain`). Hoy la
   implementación es una clave en memoria; mañana es KMS y no se entera nadie.
3. **El estado es un documento explícito** (`state/*.json`): secuencia,
   `NextUpdate`, proveedores, URL de publicación. No se deriva del `git log` ni
   del `mtime`. Versionarlo en git da el historial de versiones gratis y
   auditable: "qué decía la lista el 7 de septiembre" es `git show`.
4. **Las URLs se fijan en el estado, no en el layout del disco.** Acaban dentro
   de certificados firmados y configuradas en dispositivos ajenos; cambiarlas
   después obliga a reemitir.

## Estado

| Pieza | Estado |
|---|---|
| CA + hojas (P-256, SKI/AKI/CRL DP, DN completo con país) | ✅ `packages/ca` |
| Trusted List XML ETSI TS 119 612 v2.3.1 + firma XAdES | ✅ `packages/tl-xml` — Annex B + verificada con `@owf/eudi-tl` |
| Certificado del TLSO conforme a la cláusula 5.7.1 | ✅ `mintTlSigner` + `assertTlsoProfile` |
| Perfil **AV Trusted List** de la Comisión (tablas I.1–I.3) | ✅ `packages/tl-xml/src/av-profile.mjs` |
| Listas LoTE: PID · Wallet · **WRPAC (Access CAs)** · **WRPRC** · PubEAA | ✅ `packages/lote` — TS 119 602 v1.1.1 |
| **Access certificates de RP (WRPAC)** | ✅ `packages/ca/src/wrpac.mjs` — TS 119 411-8 v1.1.1 |
| **Registration certificates (WRPRC)** | ✅ `packages/wrprc` — TS 119 475 v1.2.1, con detector de edición |
| Status lists (revocación) | ⬜ sobre `@owf/token-status-list` |
| Firma de CSR | ⬜ solo si hace falta dar certs a terceros sin exportar claves |

## Los dos formatos, y por qué el XML es el caro

| | AV Trusted List | El resto (PID, Wallet, WRPAC, WRPRC) |
|---|---|---|
| Norma | ETSI TS 119 612 v2.4.1 | ETSI TS 119 602 v1.1.1 |
| Formato | XML `TrustServiceStatusList` | JSON LoTE |
| Firma | XAdES enveloped (Annex B) | JWS compacto |
| Quién construye | **nosotros** (`packages/tl-xml`) | `@owf/eudi-lote` |
| Quién verifica | `@owf/eudi-tl` | `jose` + la propia librería |

Sólo el XML hay que construirlo a mano: ninguna librería lo firma. El LoTE lo
cubre `@owf/eudi-lote` de punta a punta, así que ese paquete es sobre todo
vocabulario de la norma y comprobaciones.

## La norma, convertida en test

Dos comprobaciones corren en cada `build-list` y **abortan la emisión** si fallan:

- `assertAnnexB(xml)` — Annex B.1.0/B.1.1 de TS 119 612: firma enveloped, un
  `ds:Transforms` con enveloped-signature + **exclusive** c14n,
  `CanonicalizationMethod` exclusiva, y `xades:SigningCertificateV2` (no la V1).
  Ninguna de las cuatro es el default de xadesjs: las cuatro estaban mal en el
  primer intento.
- `assertTlsoProfile(cert, state)` — cláusula 5.7.1: `C`/`O` del Subject
  coincidiendo con Scheme Territory y Scheme operator name, `CA=false`,
  KeyUsage limitado a digitalSignature/nonRepudiation y EKU
  `id-tsl-kp-tslSigning` (0.4.0.2231.3.0).

- `assertAvProfile(state)` — las tablas I.1–I.3 de las *AV Trusted List
  Specifications* de la Comisión: los seis valores que fija por texto exacto
  (scheme name, scheme information URI, status determination approach, scheme
  rules, territorio "EU" y el aviso legal), el puntero a sí misma, el
  `TSPInformationURI` con el código del EM de cada PAAP, y que el estado del
  servicio sea sólo `recognized` o `deprecated`.

- `assertWrpacProfile(cert)` — cláusula 6.6.1 de TS 119 411-8: política del
  arco `0.4.0.194118.1.*`, `organizationIdentifier` en el subject DN,
  qualifier `cpsURI` y contacto del RP en el SAN. Los tres requisitos
  obligatorios se comprueban además **antes** de emitir, así que un spec
  incompleto no llega a producir certificado.
- `assertLote(lote, state)` — validez estructural según `@owf/eudi-lote`, más
  la coherencia entre el tipo de lista y los tipos de servicio de sus entidades.
  Y cada `build-lote` **se verifica a sí mismo**: comprueba la firma del JWS
  contra el certificado del firmante antes de dar la emisión por buena
  (manipular el payload o cambiar de firmante la rechaza con
  `ERR_JWS_SIGNATURE_VERIFICATION_FAILED`).

- `assertRegistry(reg)` — multiplicidades de TS5 §2.1/§2.4.1 y mínimos de TS6:
  `isPSB` obligatorio, la DPA con nombre y país, al menos un contacto por
  servicio, `serviceIdentifier` obligatorio si se usa intermediario,
  `providesAttestations` si hay entitlement de proveedor, y los tipos de
  identificador acotados a los de TS 119 475 tabla 2.

No son decorativas: firmar la lista con una CA normal, o cambiar un URI del
perfil AV, aborta la emisión con el detalle en pantalla.

### Las cuatro suites

```bash
npm test
```

### Las seis suites

```bash
npm test
```

| Suite | Qué cubre |
|---|---|
| `packages/store/test/conformance.mjs` | los tres adaptadores de almacén responden igual, SQL incluido (PGlite) |
| `test/signatures.mjs` | todo lo que se firma se relee: WRPRC y status list verifican contra el certificado de su firmante |
| `test/views.mjs` | cada vista de la consola se renderiza sin referencias rotas |
| `test/cli.mjs` | el CLI de punta a punta: monta un marco entero y comprueba lo emitido |
| `test/publisher.mjs` | el publisher sirve lo emitido **y nada más** |
| `test/console.mjs` | la consola, por HTTP: sesión, emisión, borrado y descargas |

Las tres últimas arrancan el proceso de verdad sobre una raíz temporal —copia de
`apps/`, `packages/` y `state/`, con `DATABASE_URL` y `TRUST_LAB_PGLITE`
borradas del entorno—, así que no tocan ni el repo ni ninguna base de datos.
`test/harness.mjs` es ese andamiaje.

No comprueban que los programas impriman lo que imprimen, sino las propiedades
que cuestan un despliegue:

- **CLI** — cada lista publica el certificado que le toca (la AV TL el DS, el
  anexo F la CA emisora); el `idx` que viaja firmado en el WRPRC es el que se
  reservó; reemitir mueve la posición y una lista agotada se niega **antes que
  reciclar** una liberada; un cambio de estado no se publica hasta reemitir la
  lista; un incumplimiento de perfil sale como mensaje y no como pila.
- **Publisher** — arranca **sin `TRUST_LAB_KEY`** y aun así publica (no puede
  descifrar una clave ni queriendo); cualquier método que no sea GET/HEAD es
  405; sirve en la ruta que el documento **declara**, porque esa URL viaja
  dentro de lo firmado; una versión histórica devuelve sus bytes de siempre
  después de reemitir; ninguna ruta publicada filtra material privado.
- **Consola** — no arranca sin contraseña; sin sesión no responde nada, tampoco
  la descarga de claves; una cookie con la firma tocada o caducada no vale; un
  error de operación vuelve como aviso y no como 500; y el flujo entero de
  emisión funciona pulsando botones, incluidas las operaciones que **sólo**
  existen ahí (asignar emisor a una status list, editar los miembros de una
  lista, el reset).

Las dos de servicio corren contra **SQL (PGlite)**, que es lo que hay en
producción, y no por gusto: el fallo de *"no existe"* al guardar los miembros de
una lista sólo se reproducía ahí —en fichero el documento lleva su `id` dentro y
en Postgres la clave primaria es `(kind, id)`—, y el historial de artefactos que
el publisher sirve tampoco existe en el almacén de fichero, donde lo guarda git.

## Por qué la lista de laboratorio copia el perfil AV al pie de la letra

Podría llevar un nombre de esquema propio que gritara "esto es una prueba". No
lo lleva, y es deliberado: el objetivo es que una wallet trate esta lista
**exactamente igual** que la real, y la única diferencia sea **quién la firma**
y **quién está dentro**. Un nombre distinto o un URI propio darían a una wallet
estricta un motivo para rechazarla que no es el que estamos probando. La
honestidad no vive en el contenido de la lista, vive en que nadie confía en ella
salvo quien pinea nuestro firmante a mano.

Si prefieres lo contrario, `allowDivergence: true` en el estado degrada las
comprobaciones del perfil AV a avisos.

## Un registro, dos certificados

`state/<rp>.json` es **el registro de la relying party**, con el modelo de datos
de **TS5** y los mínimos de **TS6** — el que guardaría un Registrar nacional. De
ahí salen los dos certificados, y no por gusto: GEN-6.6.1-10 de TS 119 411-8
dice que los atributos del access certificate *"shall be derived from the
information held in the register as specified in clause 5.1.2 of ETSI
TS 119 475"*.

La jerarquía de TS5 tiene un nivel que un modelo improvisado se salta:

```
WalletRelyingParty            ← la entidad legal registrada
  └── services[]              ← WalletRelyingPartyService
        └── intendedUses[]    ← un WRPRC por cada uno
              └── credentials[] → claims[]
```

El nivel «servicio» no está en el reglamento: TS5 lo añade para que un RP pueda
separar instancias, certificados de acceso y finalidades. Y el identificador
semántico (`VATES-B12345678`) se **deriva** del identificador tipado del
registro en vez de escribirse a mano en los dos certificados.

### Alta de una relying party

El esqueleto que se crea **ya valida**. La alternativa —un documento incompleto
que el editor rechaza al guardar— obligaría a rellenar cuarenta campos anidados
de una sentada antes de poder salvar nada; así se crea la entidad y a partir de
ahí se cambian valores de uno en uno con la validación de red. El precio es que
los valores de relleno son visiblemente de relleno (`PENDIENTE — …`): si alguien
emite un certificado sin tocarlos, se ve en el subject.

En la consola es el formulario del final de `/rps`. Por CLI:

```bash
node apps/cli/index.mjs new-rp bodegas-valle "Bodegas del Valle S.A." A87654321 ES status-wrprc
```

Si se le indica una lista de revocación, le **reserva una posición libre** en el
alta y no al emitir el WRPRC. Es deliberado: dos altas que eligen la misma
posición se detectan cuando no cuesta nada, y no cuando ya hay material firmado
apuntando a una posición compartida — que es como se revocan dos RP de golpe.

```bash
node apps/cli/index.mjs mint-wrpac  wrpac-issuing-ca espuni-access state/espuni-rp.json av-1
node apps/cli/index.mjs issue-wrprc state/espuni-rp.json av-1 av-over-18 tl-signer
```

### Sacarlos de la fábrica

Los dos certificados se emiten aquí pero se **usan fuera**: el access
certificate lo instala el RP en su propio despliegue y el WRPRC viaja dentro de
la petición OID4VP. Así que hay puerta de salida, y está **solo en la consola**
— la superficie autenticada. El publisher no tiene ninguna de estas rutas y no
puede descifrar ninguna clave, que es justo para lo que se separó.

```bash
# access certificate: cadena (pública), o cadena + privada
node apps/cli/index.mjs export-key espuni-rp-av-1-access chain  out/
node apps/cli/index.mjs export-key espuni-rp-av-1-access bundle out/   # 0600
node apps/cli/index.mjs export-key espuni-rp-av-1-access jwk    out/   # JWK + x5c

# registration certificate: el JWS compacto, byte a byte como se emitió
node apps/cli/index.mjs export wrprc av-1-av-over-18 out/
```

En la consola son enlaces: `/rps/<rp>` para los de una relying party, `/keys`
para cualquier clave del almacén. Las cuatro formas están detrás de la misma
autenticación, pero **solo `chain` no es secreta** — es el certificado y su
cadena, que es lo que se pinea en el otro extremo. Las otras tres llevan la
privada dentro, se marcan con 🔑, se escriben con permisos `0600` y quedan
registradas en el log del servicio.

## Revocación, de punta a punta

El WRPRC lleva `status.status_list = { idx, uri }` apuntando a una lista propia,
así que "certificado de registro revocado" deja de ser una frase y pasa a ser
un caso ejecutable:

```bash
node apps/cli/index.mjs status-check status-wrprc 7 tl-signer   # → valid
node apps/cli/index.mjs status-set   status-wrprc 7 invalid "intended use retirado"
node apps/cli/index.mjs status-build status-wrprc tl-signer
node apps/cli/index.mjs status-check status-wrprc 7 tl-signer   # → invalid
```

La lista se reserva entera de golpe (1024 posiciones) en vez de crecer con cada
revocación: una lista que crece filtra cuántos certificados hay vivos.

## v1.1.1 contra v1.2.1: seis cambios que rompen

`packages/wrprc` implementa la **v1.2.1** (la que trae `@owf/eudi-wrprc`) y
lleva la tabla de diferencias en `EDITIONS`, con un `detectEdition(header,
payload)` que dice contra qué edición se emitió un certificado ajeno:

| | v1.1.1 (2025-10) | v1.2.1 (2026-03) |
|---|---|---|
| Cabecera (tabla 5) | `typ alg x5c` **`b64` `cty`** | `typ alg x5c` |
| Sujeto | `sub.legal_name` + `sub.id` | `sub` (identificador) + `sub_ln` |
| Descripción del servicio | `service` | `srv_description` |
| Autoridad de control | `dpa` con `name`/`country` | `supervisory_authority`, **sólo contacto** |
| Claims del credential | `claims` | `claim` |
| Intermediario | `act.sub.{id,name}` | `intermediary.{sub,sname}` |

Los campos que la edición vigente ya no transporta se avisan al emitir en vez
de descartarse en silencio.

## Un solo sitio para cada operación

CLI y consola son **frontales**: parsean y presentan. Las operaciones viven en
`packages/ops` y no se implementan dos veces. Es el mismo problema que este
repositorio lleva documentando en otros sitios —lógica duplicada que diverge— y
en una fábrica de certificados la copia que diverge no se nota hasta que una
wallet dice que no.

## El almacén

`packages/store` separa el CLI del sitio donde vive el estado. Tres
colecciones: `docs` (el estado explícito), `keys` (material criptográfico) y
`artifacts` (**lo emitido y firmado, inmutable**).

| | Fichero | Postgres |
|---|---|---|
| Se elige con | *(por defecto)* | `DATABASE_URL`, o `TRUST_LAB_PGLITE` para local |
| Estado | `state/*.json` | tabla `docs` |
| Claves | `out/keys/*.json` | tabla `keys` |
| Artefactos | último en `out/`, historial en **git** | **todas** las versiones en `artifacts` |
| Cifrado de claves | opcional | **obligatorio**, fail-closed |

Los tres adaptadores —memoria, fichero y SQL— pasan la misma suite de
conformidad, y el SQL se prueba contra **Postgres de verdad** vía PGlite (el
motor compilado a WASM), no contra un simulacro:

```bash
node packages/store/test/conformance.mjs
```

### Por qué los artefactos se guardan enteros

Un artefacto firmado **no se puede reconstruir a posteriori**: la firma depende
de la clave, del instante y del orden de serialización. Guardar sólo el estado
que lo generó no permite responder *"¿qué decía exactamente la lista el 7 de
septiembre?"*. En fichero esa respuesta la daba git; en base de datos hay que
guardar el byte, y por eso `artifacts` es inmutable y sin `ON CONFLICT`:
reemitir con la misma secuencia es un error, no una actualización.

### Las claves

`TRUST_LAB_KEY` (32 bytes, hex o base64) cifra el material privado con
AES-256-GCM. En SQL es **obligatoria**: sin ella el CLI falla en vez de escribir
una clave privada en claro en una base de datos que se comparte y se respalda.
Los certificados quedan legibles sin descifrar nada —son públicos, y poder
listarlos es lo que hace operable el almacén—; sólo la privada va cifrada.

En el almacén de fichero el cifrado es opcional: ahí el material no sale de la
máquina del operador. Sigue siendo material de laboratorio y nada de esto vale
fuera de un entorno de pruebas.

## Licencia

**Apache-2.0** (ver [`LICENSE`](LICENSE) y [`NOTICE`](NOTICE)).

Se elige por compatibilidad hacia el ecosistema del que este proyecto ya
depende: las cuatro librerías de la OpenWallet Foundation que usa
(`@owf/eudi-tl`, `@owf/eudi-lote`, `@owf/eudi-wrprc`,
`@owf/token-status-list`) son Apache-2.0, y es la licencia por defecto de sus
proyectos. Con la misma licencia, el código de aquí puede moverse hacia allí
sin recompatibilizar nada.

El resto del árbol de dependencias es permisivo —MIT, Apache-2.0, BSD-3-Clause,
ISC, 0BSD— sin ninguna licencia copyleft ni de uso restringido, así que no hay
obligaciones que se propaguen a quien use esto.
