# Imunno System - EDR & Causal Analysis Platform

![Status](https://img.shields.io/badge/Status-MVP%20Validated-success) ![Version](https://img.shields.io/badge/Version-1.0.0-blue) ![Architecture](https://img.shields.io/badge/Architecture-Microservices-orange)

> **"O sistema imunológico para a web."**
> Segurança adaptativa focada em neutralizar ameaças *Zero-Day* através de Análise de Causalidade e Inteligência Artificial Contextual.

---

## 📐 Princípios de Engenharia

Este projeto foi construído sobre pilares inegociáveis que guiam cada decisão de arquitetura:

* **Simplicidade:** O código é "burro" onde pode ser, e inteligente onde precisa ser. Evitamos abstrações prematuras.
* **Manutenibilidade:** Arquitetura desacoplada para sobreviver ao tempo. Cada micro-serviço tem uma responsabilidade única e clara.
* **Complexidade Justificada:** Tecnologias complexas (como eBPF ou Time-Series DB) só são introduzidas quando a solução simples deixa de escalar.

---

## 🏗️ Arquitetura do Sistema

O Imunno System opera numa arquitetura distribuída de micro-serviços, containerizada via Docker, desenhada para baixo impacto em performance (< 0.07% CPU) e alta eficácia de detecção em ambientes Linux/WordPress.

### Componentes Principais

1.  **🛡️ Imunno Agent (Go)**
    * **Localização:** `imunno-agent/`
    * **Função:** Sentinela de borda. Monitora o Kernel Linux em tempo real.
    * **Tecnologia:** Golang nativo. Utiliza `auditd` para rastreamento de processos e `inotify` para monitoramento de sistema de arquivos.
    * **Responsabilidade:** Coleta eventos de criação de arquivos e execução de processos, envia para o Collector e executa ordens de quarentena/kill.

2.  **🧠 Imunno Collector (Go)**
    * **Localização:** `imunno-collector/`
    * **Função:** Cérebro Central e Orquestrador.
    * **Tecnologia:** API REST em Go (High Performance).
    * **Responsabilidade:** Recebe eventos dos agentes, executa a **Análise Heurística** estática, consulta o histórico para **Análise de Causalidade** e coordena a resposta com o ML Service.

3.  **🤖 ML Service (Python)**
    * **Localização:** `imunno-ml-service/`
    * **Função:** Inteligência Contextual.
    * **Tecnologia:** Python, Scikit-learn (Isolation Forest), Flask.
    * **Responsabilidade:** Detecta anomalias comportamentais que escapam às regras fixas. Classifica o risco com base em múltiplos vetores (score heurístico, entropia, extensão, etc.).

4.  **💾 Data Layer (PostgreSQL)**
    * **Localização:** `postgres-init/`
    * **Função:** Memória Persistente e Grafo de Eventos.
    * **Responsabilidade:** Armazena a "Árvore Genealógica" dos processos e arquivos (`file_events`, `process_events`), permitindo o rastreamento da origem do ataque (Patient Zero).

---

## 🚀 Fluxo de Detecção (Pipeline)

1.  **Ingestão:** O `Agent` detecta um evento (ex: `malware.php` criado via upload) e transmite ao `Collector`.
2.  **Análise Imediata:** O `Collector` calcula o Hash SHA256 e executa a Heurística (busca por padrões como `eval`, `base64`).
3.  **Inteligência:** O `Collector` consulta o `ML Service` para validar a probabilidade de anomalia estatística.
4.  **Causalidade (O Diferencial):**
    * Se um *processo* suspeito inicia, o sistema rastreia o seu `ParentID` e busca no banco de dados quem criou o arquivo executável original.
    * Se a origem for maliciosa, o ataque é confirmado por linhagem (Pai -> Filho).
5.  **Resposta:** Se o *Threat Score* > 70 (configurável), o sistema emite ordem de **Quarentena** e **Kill** imediato para o Agente.

---

## 🛠️ Instalação e Deploy (Quick Start)

### Pré-requisitos
* Docker & Docker Compose
* Linux Kernel 4.x+ (com Auditd habilitado no host)

### Rodando o Ambiente (Dev/MVP)

O sistema completo pode ser iniciado com um único comando na raiz do projeto:

```bash
# 1. Clone o repositório
git clone [https://github.com/rodrigoffreir3/imunno-system.git](https://github.com/rodrigoffreir3/imunno-system.git)

# 2. Inicie a stack completa (Build & Run)
docker-compose up -d --build

# 3. Verifique se os serviços estão rodando
docker ps

### Acesso ao Dashboard

A interface de monitoramento em tempo real (WebSocket) estará disponível em:
`http://localhost:8080`

---

## 🔌 API Endpoints (Internal)

A comunicação entre Agente e Collector é feita via REST JSON.

| Método | Endpoint | Descrição | Payload Exemplo |
| :--- | :--- | :--- | :--- |
| `POST` | `/v1/events/file` | Reporta criação/modificação de arquivos. | `{"agent_id": "uuid", "file_path": "/var/www/x.php", "content": "..."}` |
| `POST` | `/v1/events/process` | Reporta execução de processos. | `{"process_id": 123, "command": "bash -i", "parent_id": 80}` |
| `POST` | `/v1/whitelist/add` | Adiciona hash à lista segura (Feedback Loop). | `{"file_hash": "sha256...", "file_path": "..."}` |

---

## 🗺️ Roadmap Tecnológico (v2: Escala Industrial)

O projeto segue um roadmap de evolução para escala massiva e autonomia biológica.

### v2: Architecture for Scale (Next Milestone)
- [ ] **Arquitetura Assíncrona:** Implementação de NATS JetStream/RabbitMQ para ingestão de eventos via filas (amortecedor de picos).
- [ ] **Time-Series DB:** Migração da ingestão de logs brutos para ClickHouse (alta performance de escrita).
- [ ] **eBPF:** Evolução do Agente para monitoramento via Extended Berkeley Packet Filter (Zero-Overhead e invisibilidade).
- [ ] **Segurança:** Implementação de mTLS entre Agente/Collector e Hardening do Agente (Imutabilidade).

### v3: Imunno Green & Oscar (R&D)
- [ ] **Eficiência Energética:** Monitoramento de consumo (Watts) por processo via RAPL e eco-throttling.
- [ ] **Vida Artificial:** Agentes autônomos com homeostase e comunicação P2P (Gossip Protocol).

---

© 2025 Imunno System. Todos os direitos reservados.
