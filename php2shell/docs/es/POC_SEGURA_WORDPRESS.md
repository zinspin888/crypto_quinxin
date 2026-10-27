# Laboratorio seguro de PHP2Shell sobre WordPress

Este laboratorio muestra el runtime web efectivo y el ciclo `status → OOM → status`. El OOM se provoca después de cargar WordPress mediante un máximo fijo de 24 bloques de 1 MiB y un límite temporal situado 8 MiB por encima del consumo inicial.

No implementa una cadena de PHP2Shell: no envía multipart anómalos, no interrumpe `unserialize()`, no prepara el heap, no consume punteros obsoletos, no lee memoria y no ejecuta comandos. Un OOM o un HTTP 500 aislado no demuestra la CVE; el resultado sirve para observar el manejo fatal y la reutilización del worker.

## Protecciones del laboratorio

- Compose publica Apache únicamente en `127.0.0.1:8080`.
- El endpoint requiere `PHP2SHELL_LAB_ENABLED=1` y la cabecera con token.
- El cliente rechaza cualquier destino que resuelva fuera de loopback y no sigue redirecciones.
- La petición OOM no acepta tamaños ni funciones suministrados por HTTP y se envía una sola vez.
- La salida verbosa oculta el token.

El token incluido es una credencial desechable de laboratorio. No reutilizarlo y eliminar el endpoint al terminar.

## Puesta en marcha

Desde `wp-7.1.1`:

```sh
docker compose config --quiet
docker compose up -d --force-recreate wordpress
docker compose exec -T wordpress php -l /var/www/html/php2shell-lab.php
```

Comprobar únicamente versión, SAPI y configuración:

```sh
python3 ../php2shell_safe_probe.py
```

Ejecutar una sola prueba OOM y observar la recuperación:

```sh
python3 ../php2shell_safe_probe.py --trigger-oom
```

Correlacionar los identificadores de petición y los PID con el log:

```sh
docker compose logs --no-color --since 2m wordpress | rg 'PHP2SHELL_LAB|Allowed memory size|Out of memory'
```

El endpoint registra `oom_start` antes de reservar memoria y `oom_shutdown` al terminar. WordPress tiene deshabilitada su pantalla de recuperación solo dentro de este Compose para que el fatal resulte más determinista.

## Interpretación

| Resultado | Interpretación correcta |
| --- | --- |
| `STATUS_ONLY` | Se obtuvo el runtime web real. La clasificación por versión no detecta backports del proveedor. |
| `RECOVERED_SAME_WORKER` | El mismo proceso observado atendió otra petición tras un OOM benigno. No prueba ni descarta PHP2Shell. |
| `WORKER_REPLACED_OR_NOT_RESAMPLED` | Otro worker respondió o el inicial no apareció en las muestras; con varios workers es inconcluso. |
| `FAILED` | El endpoint no respondió o WordPress no se recuperó en la ventana observada. Revisar logs y límites del contenedor. |

La imagen actual observada usa PHP 8.3.33. Esa cadena de versión está dentro del rango upstream afectado y la primera release upstream corregida de la rama es 8.3.36. Un proveedor podría haber aplicado un backport manteniendo el número, por lo que la versión es evidencia de exposición, no una prueba de explotación.

## Resultado observado en este entorno

La ejecución del 21 de octubre de 2026 obtuvo:

- WordPress 7.1.1 sobre PHP 8.3.33, SAPI `apache2handler` y `mod_php` cargado.
- `memory_limit=128M`, `post_max_size=8M`, OPcache y progreso de uploads de sesión habilitados.
- La petición intencional `lab-3ad3359907664f2a` instaló un límite temporal de 12 MiB en el PID 22.
- El log registró el comienzo, el fatal de memoria al solicitar 1.052.672 bytes y el shutdown correlacionado.
- Una petición posterior volvió a ser atendida por el PID 22.
- Docker informó `running=true`, `OOMKilled=false`, `Restarting=false` y no recreó el contenedor.

El HTTP de la petición OOM fue 200 porque la cabecera y el primer bloque JSON ya se habían enviado cuando ocurrió el fatal. Por eso el cliente correlaciona el evento con los logs en vez de interpretar el código HTTP como prueba.

Durante la primera validación, WordPress eliminó una variable global genérica del endpoint y una consulta `status` activó accidentalmente el OOM. Se corrigió guardando la acción y el identificador en constantes antes del bootstrap; la validación posterior separó correctamente ambas acciones. Los logs conservan ese ensayo anterior (`lab-36f4c77843a742f7`) para que el historial sea explícito.

El resultado verificado es **recuperación del mismo worker después de un OOM benigno**. No demuestra el use-after-free, una fuga de memoria ni RCE.

Para comparar vulnerable/corregido, conservar WordPress, extensiones y configuración, cambiar únicamente el runtime y usar el mismo harness. La evidencia específica del arreglo sigue siendo la versión o backport acreditado, los PHPT del parche y, si se compila un laboratorio instrumentado, la ausencia de errores nativos en esas pruebas.

## Retirada

Al terminar, eliminar `wp/php2shell-lab.php` y las variables `PHP2SHELL_LAB_*` de Compose, retirar `WP_DISABLE_FATAL_ERROR_HANDLER` y recrear el servicio. El archivo de laboratorio permite una denegación de servicio deliberada a quien conozca el token, aunque el puerto esté ligado a loopback.
