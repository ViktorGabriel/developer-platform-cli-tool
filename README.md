# CloudSec & Container Audit CLI

[![CI Pipeline](https://github.com/ViktorGabriel/developer-platform-cli-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/ViktorGabriel/developer-platform-cli-tool/actions)
![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)
![Pydantic](https://img.shields.io/badge/pydantic-v2-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

Ferramenta CLI empresarial de auditoria de segurança estática e dinâmica para infraestrutura como código (IaC), Dockerfiles, contêineres em execução e arquivos de configuração (YAML/JSON).

---

## 🎯 Funcionalidades Principais

1. **Inspeção Estática de Dockerfile:**
   - Detecção de execução como usuário `root` (ausência de diretiva `USER` não-root).
   - Identificação de portas sensíveis/perigosas expostas (`EXPOSE 22`, `EXPOSE 23`, `EXPOSE 3389`, etc.).
   - Alertas para uso de tags flutuantes (`latest`) e padrões inseguros como `curl | bash`.

2. **Auditoria de Contêineres Locais:**
   - Inspeção de contêineres Docker em execução via Docker Engine API.
   - Verificação de modo privilegiado (`--privileged`), execução como root e mapeamento excessivo de portas.

3. **Varredura de Segredos em Configurações (YAML/JSON):**
   - Detecção heurística e por expressões regulares de chaves privadas (RSA/OPENSSH), tokens de API, credenciais AWS e segredos mockados ou expostos.

4. **Relatórios Multi-Formato:**
   - **Terminal:** Tabelas formatadas e painéis de severidade com [Rich](https://rich.readthedocs.io/).
   - **JSON:** Formato estruturado para integração com pipelines de CI/CD.
   - **Markdown:** Sumário técnico para PRs e documentações de auditoria.

---

## 🚀 Instalação e Configuração

### Pré-requisitos
- Python 3.12+
- Gerenciador de dependências [uv](https://docs.astral.sh/uv/) ou `pip`

```bash
# Clonar o repositório
git clone https://github.com/ViktorGabriel/developer-platform-cli-tool.git
cd developer-platform-cli-tool

# Criar ambiente virtual e instalar dependências
uv venv
# No Windows:
.venv\Scripts\activate
# No Linux/macOS:
source .venv/bin/activate

# Instalar o pacote em modo de desenvolvimento
uv pip install -e ".[dev]"
```

---

## 💻 Guia de Uso da CLI

### 1. Inspecionar Dockerfile
```bash
cloudsec scan-dockerfile ./Dockerfile --format table
cloudsec scan-dockerfile ./Dockerfile --format json --output report.json
cloudsec scan-dockerfile ./Dockerfile --format markdown --output report.md
```

### 2. Inspecionar Contêineres Locais
```bash
# Inspecionar todos os contêineres em execução
cloudsec scan-containers

# Inspecionar contêiner específico por ID ou nome
cloudsec scan-containers --container-id my-app-container
```

### 3. Varrer Configurações (YAML/JSON) em Busca de Segredos
```bash
cloudsec scan-config ./config.yaml
cloudsec scan-config ./k8s-manifest.json --format table
```

### 4. Auditoria Geral do Repositório / Diretório
```bash
cloudsec scan-all ./ --format table
```

---

## 🧪 Execução de Testes e Qualidade de Código

```bash
# Executar a suíte de testes unitários com cobertura
uv run pytest --cov=cloudsec --cov-report=term-missing

# Verificação de tipos estáticos
uv run mypy src tests

# Linter e formatação com Ruff
uv run ruff check src tests
```

---

## ⚙️ Integração Contínua (CI/CD)

O pipeline do GitHub Actions em [.github/workflows/ci.yml](.github/workflows/ci.yml) valida a cada push e pull request:
- Linter e checagem de estilo com Ruff
- Tipagem estrita com Mypy
- Cobertura completa de testes unitários com Pytest em Python 3.12

---

## 📄 Licença

Distribuído sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE) para obter mais informações.
