# routerscope

**Busca instantânea, diff no tempo e um navegador estilo Winbox para configs e sessões CLI de roteadores multi-vendor. Funciona com qualquer terminal.**

[English](README.md) · [Português](README.pt-BR.md) · [Español](README.es.md)

> **Funciona com qualquer terminal:** Termius, PuTTY, SecureCRT, MobaXterm, Windows Terminal, OpenSSH, Tabby, iTerm. Sem plugin de terminal.

> ⚠️ **Pre-alpha.** Ainda não há nada utilizável. Acompanhe o repositório ou pegue uma [good first issue](https://github.com/dalcorsogabriel/routerscope/issues?q=is%3Aopen+label%3A%22good+first+issue%22).

## Por quê

*Tudo que seus roteadores já te mostraram, e tudo que está configurado neles, pesquisável em milissegundos. Navegue como no Winbox, em qualquer fabricante. Teste uma mudança antes de aplicar.*

Engenheiros de rede perdem minutos todo dia rolando histórico de terminal, dando grep em backup de config e perguntando "como estava o `display bgp peer` antes da janela de ontem?". As ferramentas existentes cobrem bem Cisco/Juniper/Arista e mal **Huawei VRP, MikroTik RouterOS e Nokia SR OS**. O routerscope ocupa esse espaço.

## O que vai fazer

- **Busca instantânea** em configs, saídas de comando e histórico: texto livre, **IP/prefixo com contenção** (`200.0.0.0/22` acha tudo dentro ou que o contém), MAC em qualquer formato, ASN, communities, VLAN, nomes de interface normalizados entre vendors, nomes de policy/prefix-list/ACL/VRF.
- **Linha do tempo e diff semântico**: compara saídas por chave natural (peer, interface, prefixo), ignorando contadores, uptime e timestamps. Diff hierárquico de config.
- **"Onde está?"**: em quais equipamentos/interfaces/VRFs aparece um IP, MAC, VLAN ou prefixo.
- **Navegador estilo Winbox (read-first)** para todos os vendors, com navegação por referência, **where-used**, referências quebradas e objetos sem uso.
- **Sugestões** com evidência e snippet de correção + rollback no dialeto do vendor. Nunca aplica sozinho.
- **Simulação what-if**: testar rota contra a policy de um peer, impacto de mudança, falha de enlace, export de lab.
- **CLI, API local e servidor MCP read-only** para assistentes de IA consultarem o índice.

## Como captura dados (sem depender de terminal)

1. **Importadores**: logs de SecureCRT/PuTTY/MobaXterm/Windows Terminal/Tabby/iTerm, repositórios Oxidized e RANCID, ou colar texto.
2. **Proxy SSH local gravador**: configure `localhost` como jump host em qualquer cliente SSH (Host Chaining no Termius, `ProxyJump` no OpenSSH...).
3. **Collector read-only**: gentil, com rate limit, nunca muda config persistente; todo comando passa pelo [`netcmd-safety`](packages/netcmd-safety).

## Princípios

Somente leitura por padrão · local-first, sem telemetria · Windows, Linux e macOS · segredos no keyring do SO · extensível por plugins.

## Fabricantes

Huawei VRP · MikroTik RouterOS 7 · Nokia SR OS (classic e MD-CLI) · IP Infusion OcNOS · Cisco IOS/IOS-XE/IOS-XR · Juniper Junos.

## Roadmap

| Versão | Tema |
|---|---|
| v0.1 | "Everything offline": importadores, segmentação, busca, diff, CLI, UI mínima, `netcmd-safety` no PyPI |
| v0.2 | Captura independente de terminal: proxy SSH gravador, collector read-only |
| v0.3 | Navegador estilo Winbox, where-used, locate, servidor MCP |
| v0.4 | Regras de sugestão (higiene BGP/MANRS) com snippets de correção e rollback |
| v0.5 | Testador de policy e análise de impacto |
| v0.6 | What-if de falha, export de lab, escrita segura opt-in |

## Contribuindo

As formas mais fáceis de ajudar não exigem conhecer o código: uma **fixture sanitizada** de um comando no seu vendor/versão, um **parser** de um comando ou uma **regra YAML**. Veja o [CONTRIBUTING.md](CONTRIBUTING.md) (em inglês). Issues e PRs em português são bem-vindos; o código e a documentação ficam em inglês.

## Licença

[Apache-2.0](LICENSE)
