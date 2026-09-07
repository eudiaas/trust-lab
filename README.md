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
| Trusted List XML ETSI TS 119 612 + firma XAdES | ✅ `packages/tl-xml` — verificada con `@owf/eudi-tl` |
| Listas LoTE (PID providers, wallet providers, Access CAs) | ⬜ sobre `@owf/eudi-lote` |
| Registration certificates (WRPRC) | ⬜ sobre `@owf/eudi-wrprc` (v1.2.1) |
| Status lists (revocación) | ⬜ sobre `@owf/token-status-list` |
| Firma de CSR | ⬜ solo si hace falta dar certs a terceros sin exportar claves |

## Aviso

Las claves privadas se escriben en `out/keys/*.json` **en claro**. Es material de
laboratorio: `out/` no se commitea, y nada de esto vale fuera de un entorno de
pruebas. El día que esto viva en CI, las claves salen de un secret store, que es
justo lo que el contrato 2 deja abierto.
