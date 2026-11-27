# routerscope

**Búsqueda instantánea, diff en el tiempo y un navegador estilo Winbox para configuraciones y sesiones CLI de routers multi-vendor. Funciona con cualquier terminal.**

[English](README.md) · [Português](README.pt-BR.md) · [Español](README.es.md)

> **Funciona con cualquier terminal:** Termius, PuTTY, SecureCRT, MobaXterm, Windows Terminal, OpenSSH, Tabby, iTerm. Sin plugins de terminal.

> ⚠️ **Proyecto experimental.** routerscope está en una fase temprana y experimental, en desarrollo activo. Los comandos, las APIs y el formato de la base de datos pueden cambiar sin aviso, y todavía no se validó a escala con equipos reales. No lo uses en producción.
>
> La aplicación todavía no es utilizable. Tres bibliotecas independientes ya se pueden probar desde el código fuente: [`netcmd-safety`](packages/netcmd-safety), [`netprompt`](packages/netprompt) y [`netaddr-search`](packages/netaddr-search). Sigue el repositorio o toma un [good first issue](https://github.com/dalcorsogabriel/routerscope/issues?q=is%3Aopen+label%3A%22good+first+issue%22).

## Por qué

*Todo lo que tus routers te mostraron alguna vez, y todo lo que tienen configurado, buscable en milisegundos. Navega como en Winbox, en cualquier fabricante. Prueba un cambio antes de aplicarlo.*

Los ingenieros de red pierden minutos cada día recorriendo el historial de la terminal, haciendo grep en backups de configuración y preguntándose "¿cómo estaba el `display bgp peer` antes de la ventana de anoche?". Las herramientas existentes cubren bien Cisco/Juniper/Arista y mal **Huawei VRP, MikroTik RouterOS y Nokia SR OS**. routerscope llena ese vacío.

## Qué hará

- **Búsqueda instantánea** en configuraciones, salidas de comandos e historial: texto libre, **contención de IP/prefijo** (`192.0.2.0/24` encuentra todo lo que está dentro o lo contiene), MAC en cualquier formato, ASN, communities, VLAN, nombres de interfaz normalizados entre fabricantes, nombres de policy/prefix-list/ACL/VRF.
- **Línea de tiempo y diff semántico**: compara salidas por clave natural (peer, interfaz, prefijo), ignorando contadores, uptime y timestamps. Diff jerárquico de configuración.
- **"¿Dónde está?"**: en qué equipos/interfaces/VRFs aparece una IP, MAC, VLAN o prefijo.
- **Navegador estilo Winbox (read-first)** para todos los fabricantes, con navegación por referencias, **where-used**, referencias rotas y objetos sin uso.
- **Sugerencias** con evidencia y snippet de corrección + rollback en el dialecto del fabricante. Nunca se aplican solas.
- **Simulación what-if**: probar una ruta contra la policy de un peer, impacto de un cambio, falla de enlace, exportar un laboratorio.
- **CLI, API local y servidor MCP de solo lectura** para que asistentes de IA consulten el índice.

## Cómo captura datos (sin depender de la terminal)

1. **Importadores**: logs de SecureCRT/PuTTY/MobaXterm/Windows Terminal/Tabby/iTerm, repositorios Oxidized y RANCID, o pegar texto.
2. **Proxy SSH local que graba**: configura `localhost` como jump host en cualquier cliente SSH (Host Chaining en Termius, `ProxyJump` en OpenSSH...).
3. **Collector de solo lectura**: respetuoso, con rate limit, nunca cambia la configuración persistente; cada comando pasa por [`netcmd-safety`](packages/netcmd-safety).

## Principios

Solo lectura por defecto · local-first, sin telemetría · Windows, Linux y macOS · secretos en el keyring del SO · extensible con plugins.

## Fabricantes

Huawei VRP · MikroTik RouterOS 7 · Nokia SR OS (classic y MD-CLI) · IP Infusion OcNOS · Cisco IOS/IOS-XE/IOS-XR · Juniper Junos.

## Roadmap

| Versión | Tema |
|---|---|
| v0.1 | "Everything offline": importadores, segmentación, búsqueda, diff, CLI, UI mínima, `netcmd-safety` en PyPI |
| v0.2 | Captura independiente de la terminal: proxy SSH que graba, collector de solo lectura |
| v0.3 | Navegador estilo Winbox, where-used, locate, servidor MCP |
| v0.4 | Reglas de sugerencia (higiene BGP/MANRS) con snippets de corrección y rollback |
| v0.5 | Probador de policy y análisis de impacto |
| v0.6 | What-if de fallas, exportación de laboratorio, escritura segura opt-in |

## Contribuir

Las formas más fáciles de ayudar no requieren conocer el código: un **fixture sanitizado** de un comando en tu fabricante/versión, un **parser** de un comando o una **regla YAML**. Ver [CONTRIBUTING.md](CONTRIBUTING.md) (en inglés). Issues y PRs en español son bienvenidos; el código y la documentación quedan en inglés.

## Licencia

[Apache-2.0](LICENSE)
