# Upstream Sync — Baseline (2026-05-26)

Estado de referência antes da próxima ronda de catchup com `opendatateam/udata`.

## Snapshot do fork

| Item | Valor |
|---|---|
| Snapshot tag (local) | `pre-upstream-sync-2026-05-26` |
| SHA em `origin/main` | `e97705c260badc1bdbee9ea922c12d888f08be3f` |
| Data | 2026-05-22 15:47:45 +0100 |
| Último commit | `Merge pull request #74 from amagovpt/fix/home-endpoint-org-logo` |
| `pyproject.toml` declara | `version = "15.1.0"` ⚠️ desatualizado |
| Versão real (git-wise) | Inclui upstream até `v16.0.0` (`feat!: new api key system #3636`) |
| SHA submódulo no monorepo | `e97705c260...` |

> **Nota sobre `pyproject.toml`**: o git ancestry mostra `v16.0.0` já integrado, mas a string da versão nunca foi bumpada nos PRs de sync anteriores. Um dos primeiros lotes deve corrigir isto.

## Estado do upstream `opendatateam/udata` no fetch desta baseline

| Item | Valor |
|---|---|
| HEAD branch | `main` |
| Última tag | `v16.5.0` (2026-05-18) |
| Commits unreleased pós-`v16.5.0` | 10 |

## Divergência

| Métrica | Commits |
|---|---|
| No fork ausentes do upstream (`local-only`) | 192 |
| No upstream ausentes do fork (`upstream-only`) | 52 |

Relatórios brutos em `reports/sync/` (gitignored): `upstream-only.txt`, `local-only.txt`.

Classificação detalhada commit-a-commit:

- Total global: [`docs/sync/CLASSIFICATION-v16.x.md`](CLASSIFICATION-v16.x.md) — 52 commits, 8 HOTSPOT, 44 REVIEW.
- Lote 1 (`origin/main..v16.1.0`): [`docs/sync/CLASSIFICATION-batch-v16.1.0.md`](CLASSIFICATION-batch-v16.1.0.md) — 4 commits, 1 HOTSPOT (#3711 `access_type filter on RDF catalogs`).
- Gerar para um lote específico: `python3 scripts/classify_upstream_commits.py --range <baseTag>..<headTag> --out docs/sync/CLASSIFICATION-batch-<headTag>.md`.

## Distribuição dos 52 commits a integrar

| Lote | Commits |
|---|---|
| `v16.0.0..v16.1.0` | 10 |
| `v16.1.0..v16.2.0` | 3 |
| `v16.2.0..v16.3.0` | 18 |
| `v16.3.0..v16.4.0` | 9 |
| `v16.4.0..v16.5.0` | 8 |
| `v16.5.0..upstream/main` (unreleased) | 4 |

## Migrations

Sem colisões de nome detectadas.

- **Locais (apenas no fork):**
  - `2026-03-17-create-metrics-events-collection.py`
  - `2026-05-08-sanitize-stored-html-xss.py`
- **Upstream a integrar (não no fork):**
  - `2026-03-26-move-blocs-from-pages-to-posts-and-site.py` (lote `v16.0.0..v16.1.0`)
  - `2026-04-01-fix-report-subject-dbref-format.py`

## Cobertura de testes — baseline

**Estratégia escolhida:** usar o último build verde do CircleCI como referência, sem correr `pytest --cov` localmente.

| Item | Valor |
|---|---|
| Branch | `main` |
| SHA | `e97705c260...` |
| Total ficheiros de teste | 329 |
| Framework | pytest 9.x + pytest-cov 7.x |
| CI matrix | Python 3.11 + Python 3.13 × MongoDB 7.0.28 |

> **TODO**: preencher abaixo o número e link do último build CircleCI verde **antes** de abrir o primeiro PR de sync. O delta de cobertura de cada PR deve ser comparado contra este build.

- Último build verde de referência: `<a preencher quando se abrir o 1.º PR de sync>`
- Link: `<a preencher>`

## API contract snapshot

**Estratégia escolhida:** adiar até alguém ter `inv serve` a correr localmente. Será capturado antes do 1.º lote ser merged em `main`.

Quando aplicável, gravar em `docs/sync/api-snapshot-baseline.json`:

```bash
curl -s http://localhost:7000/api/1/swagger.json > docs/sync/api-snapshot-baseline.json
```

Cada PR de sync deve correr o mesmo dump após resolver conflitos e fazer diff contra o baseline.

## Pre-commit & lint

| Item | Estado |
|---|---|
| Pre-commit hook instalado | ✅ `pre-commit install` foi corrido em 2026-05-26 |
| Ruff configurado | ✅ via `pyproject.toml` (`extend-select = ["I"]`, line-length 100) |

## Hotspots de customização (referência para revisão por lote)

Caminhos relativos a `udata/`. Qualquer commit upstream que toque nestes ficheiros tem de ser revisto manualmente:

- `auth/saml/saml_plugin/saml_govpt.py`
- `harvest/backends/dadosgov.py`, `harvest/backends/ckanpt.py`, `harvest/backends/odspt.py`
- `harvest/url_filter.py`
- `core/dataset/api.py`, `core/dataset/download_proxy.py`
- `core/site/api.py`
- `core/organization/api.py`
- `core/user/api.py`
- `settings.py`, `udata.cfg`
- `translations/` (locale PT)

## Procedimento de rollback (pré-validado)

Em caso de regressão pós-deploy de qualquer lote:

```bash
# 1. Identificar o merge commit do lote
git log --oneline --merges -10

# 2. Reverter (NÃO usar reset --hard)
git revert -m 1 <merge-sha>

# 3. Abrir PR de revert, fazer merge, deploy
# 4. Bumpar submódulo no monorepo dadosgov para o SHA pós-revert
```

Para restaurar o estado da baseline:

```bash
git checkout pre-upstream-sync-2026-05-26
# inspeccionar, mas NÃO force-push para main
```
