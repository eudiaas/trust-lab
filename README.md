# trust-lab — v0 (opción C)

Fábrica de material de confianza para probar wallets EUDI. **No es un servicio**:
es un CLI que emite artefactos firmados estáticos. Publicarlos es `nginx`.

```bash
node apps/cli/index.mjs mint-ca    tl-signer "C=ES, O=espuni Trust Lab, CN=Trust Lab Scheme Operator"
node apps/cli/index.mjs mint-ca    av-iaca   "C=ES, O=Lab AV Attestation Provider, CN=Lab AV IACA"
node apps/cli/index.mjs mint-leaf  av-iaca av-ds "C=ES, O=Lab AV Attestation Provider, CN=Lab AV DS 01"
node apps/cli/index.mjs add-provider av-lab av-ds "Lab AV Attestation Provider"
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
| Registration certificates (WRPRC) | ⬜ sobre `@owf/eudi-wrprc` (v1.2.1) |
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

No son decorativas: firmar la lista con una CA normal, o cambiar un URI del
perfil AV, aborta la emisión con el detalle en pantalla.

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

## Aviso

Las claves privadas se escriben en `out/keys/*.json` **en claro**. Es material de
laboratorio: `out/` no se commitea, y nada de esto vale fuera de un entorno de
pruebas. El día que esto viva en CI, las claves salen de un secret store, que es
justo lo que el contrato 2 deja abierto.
