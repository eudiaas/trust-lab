# Desplegar en Railway

Dos servicios sobre **un mismo Postgres**. Es lo que hace que la consola y el
publisher vean lo mismo: en Railway el disco es efímero y no se comparte, así que
el almacén de fichero no vale aquí — el código lo rechaza explícitamente en vez
de arrancar y perderlo todo en el siguiente despliegue.

```
┌────────────────────┐        ┌──────────────────────┐
│ trust-lab-console  │        │ trust-lab-publisher  │
│ escritura, login   │        │ lectura, público     │
│ TRUST_LAB_KEY ✓    │        │ TRUST_LAB_KEY ✗      │
└─────────┬──────────┘        └──────────┬───────────┘
          └───────────► Postgres ◄───────┘
```

Que el publisher **no** tenga `TRUST_LAB_KEY` no es un olvido: es la razón de que
sean dos servicios. El proceso expuesto a internet no puede descifrar ninguna
clave privada aunque lo comprometan.

## 1. Proyecto y base de datos

1. Nuevo proyecto en Railway, desplegando desde `eudiaas/trust-lab`.
2. Añade el plugin **Postgres**. Railway inyecta `DATABASE_URL`.
3. Usa la URL **interna** (`postgres.railway.internal`), que es la que Railway
   pone por defecto en las variables referenciadas. La pública pasa por un proxy
   con TLS propio y da errores de certificado.

## 2. Servicio `trust-lab-publisher`

| Ajuste | Valor |
|---|---|
| Root Directory | *(raíz del repo)* |
| Config as code | `apps/publisher/railway.json` |
| `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` |
| `MAX_CACHE_SECONDS` | opcional (3600) |
| Dominio | **público**: es lo que descargan las wallets |

## 3. Servicio `trust-lab-console`

| Ajuste | Valor |
|---|---|
| Root Directory | *(raíz del repo)* |
| Config as code | `apps/console/railway.json` |
| `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` |
| `TRUST_LAB_KEY` | **32 bytes**: `openssl rand -hex 32` |
| `CONSOLE_PASSWORD` | sin ella el servicio no arranca |
| `CONSOLE_SECRET` | opcional; si falta, las sesiones caducan al reiniciar |
| Dominio | privado o con acceso restringido |

⚠ **`TRUST_LAB_KEY` no se rota ni se pierde.** Cifra las claves privadas de las
CAs y de los firmantes de listas. Sin ella no se puede reemitir nada, y como el
pin de un firmante *es* su clave, perderla invalida todo lo publicado para
cualquiera que lo tuviera pineado. Guárdala fuera de Railway también.

## 4. El dominio, antes de emitir nada

Las URLs de publicación viajan **dentro de artefactos firmados**: el `sub` de
cada status list, el puntero de la AV TL a sí misma, el `status.status_list.uri`
de cada WRPRC. Cambiarlas después obliga a reemitir todo y a reconfigurar a quien
las haya pineado.

Así que primero fija el dominio del publisher, y luego pon esa base en el campo
`url` de cada documento de estado (`/lists` → Editar en la consola).

## 5. Comprobación

```bash
curl -s https://<publisher>/            # índice de lo publicado
curl -sI https://<publisher>/lists/av-lab.xml | grep -i content-type
# → application/vnd.etsi.tsl+xml
curl -s -X POST https://<publisher>/lists/av-lab.xml
# → 405, este servicio es de solo lectura
```

Y desde la consola: `Estado` debe listar cada lista con lo que le falta o el
botón de emitir.

## Lo que está probado y lo que no

- ✅ Instalación de producción (`npm ci --omit=dev`) y arranque de los dos
  servicios sin dependencias de desarrollo.
- ✅ El esquema SQL y todas las operaciones contra Postgres real (PGlite, el
  motor compilado a WASM: mismo SQL, mismo comportamiento).
- ✅ El rechazo a arrancar en Railway sin `DATABASE_URL`, y sin
  `CONSOLE_PASSWORD` en la consola.
- ⚠ **No probado**: el driver `pg` contra un servidor Postgres real y la
  resolución de red de Railway. Es el único tramo que sólo se puede verificar
  desplegando.
