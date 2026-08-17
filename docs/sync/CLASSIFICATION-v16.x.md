# Upstream sync classification — `origin/main..upstream/main`

Total commits: **52**

| # | Class | SHA | Subject | Files touched |
|---|---|---|---|---|
| 1 | **HOTSPOT** | `ddaf546eb` | chore: add access_type filter on list api endpoints and rdf catalogs (#3711) | udata/core/dataservices/search.py, udata/core/dataset/api.py, udata/core/organization/api.py (+4 more) |
| 2 | **REVIEW** | `829a4f2a8` | feat: moderation dashboard improvements (#3713) | udata/core/discussions/api.py, udata/core/discussions/models.py, udata/core/reports/models.py (+4 more) |
| 3 | **REVIEW** | `bc75acae9` | fix: duplicate dataset in test (#3715) | udata/tests/api/test_datasets_api.py |
| 4 | **REVIEW** | `8d84cef74` | Bump version 16.1.0 | CHANGELOG.md |
| 5 | **REVIEW** | `4eaf3dc95` | feat: remove pages to only keep edito blocs (#3706) | udata/api/__init__.py, udata/api_fields.py, udata/commands/fixtures.py (+21 more) |
| 6 | **REVIEW** | `3c1d8ad1b` | fix: mask rename to page_mask (#3718) | udata/core/contact_point/models.py |
| 7 | **REVIEW** | `c5eca9cd6` | Bump version 16.2.0 | CHANGELOG.md |
| 8 | **HOTSPOT** | `18e997454` | feat: migrate organizations to new API fields (#3710) | udata/api_fields.py, udata/core/activity/api.py, udata/core/dataset/api_fields.py (+19 more) |
| 9 | **REVIEW** | `26c3949b4` | fix: marshalling nested reference by string (#3719) | udata/api_fields.py, udata/core/organization/models.py, udata/tests/api/test_organizations_api.py |
| 10 | **REVIEW** | `92921f393` | fix(harvest): missing new (Geo)DCAT-AP mapping for dct:provenance and dct:*rights (#3720) | udata/core/dataset/rdf.py, udata/harvest/tests/dcat/catalog.xml, udata/harvest/tests/test_dcat_backend.py (+2 more) |
| 11 | **REVIEW** | `732e2ce59` | chore(deps): update deps (#3723) | udata/tests/api/test_auth_api.py, uv.lock |
| 12 | **HOTSPOT** | `3028fdd6d` | feat: add viz poc 1 (#3680) | udata/api/__init__.py, udata/api_fields.py, udata/core/organization/api.py (+16 more) |
| 13 | **REVIEW** | `621e565c7` | fix: errors on high pages on search endpoints (#3729) | udata/search/query.py, udata/tests/apiv2/test_reuses.py |
| 14 | **REVIEW** | `3e3d1cd2d` | chore(deps): update deps (#3730) | udata/tests/api/test_security_api.py, uv.lock |
| 15 | **REVIEW** | `dc27c6cad` | fix: reintroduce oauth_authorize template (#3731) | udata/templates/api/oauth_authorize.html |
| 16 | **REVIEW** | `7a2cbd97a` | feat: expose callbacks_count for reports (#3726) | udata/api_fields.py, udata/core/reports/models.py, udata/tests/api/test_reports_api.py |
| 17 | **REVIEW** | `3676755df` | feat: better user commands output (#3733) | udata/core/user/commands.py |
| 18 | **REVIEW** | `1ee76fa82` | feat: migrate topics to api fields (#3695) | udata/api_fields.py, udata/core/spatial/models.py, udata/core/topic/api_fields.py (+4 more) |
| 19 | **REVIEW** | `ecce6b765` | chore(deps): update dependency lxml to v6.1.0 [security] (#3736) | uv.lock |
| 20 | **REVIEW** | `7e925d849` | chore: use renovate best practices config (#3740) | renovate.json |
| 21 | **REVIEW** | `9bbd56ced` | chore(config): migrate Renovate config (#3743) | renovate.json |
| 22 | **REVIEW** | `42d0534e5` | fix(harvest): invalid remote URL on record identifiers with "urn:uuid" codespace (#3724) | udata/rdf.py, udata/tests/dataset/test_dataset_rdf.py |
| 23 | **REVIEW** | `5816918d2` | feat: add harvest config in csv export (#3734) | udata/harvest/backends/base.py, udata/harvest/csv.py, udata/harvest/tests/test_csv_adapter.py |
| 24 | **REVIEW** | `4ee17fc74` | feat: add spam detection to all objects (#3717) | udata/core/dataservices/models.py, udata/core/dataset/models.py, udata/core/organization/models.py (+6 more) |
| 25 | **REVIEW** | `5c7907c9c` | Bump version 16.3.0 | CHANGELOG.md |
| 26 | **REVIEW** | `1083db093` | feat(harvest): use distribution service protocol as format when available (#3749) | udata/core/dataset/rdf.py, udata/rdf.py, udata/tests/dataset/test_dataset_rdf.py |
| 27 | **HOTSPOT** | `b4f0cd7ef` | refactor: ping on tchap (#3750) | udata/notifications/__init__.py, udata/notifications/mattermost.py, udata/notifications/tchap.py (+1 more) |
| 28 | **REVIEW** | `2bea07d5c` | fix: incorrect mask on topic element (#3756) | udata/api_fields.py, udata/tests/apiv2/test_topics.py |
| 29 | **HOTSPOT** | `2804826b0` | fix(harvest): distributions of separate WFS/WMS/WMTS layers override eachother (#3752) | udata/core/dataset/api.py, udata/core/dataset/apiv2.py, udata/core/dataset/constants.py (+13 more) |
| 30 | **HOTSPOT** | `404227ea8` | fix: membership api with user=None (#3754) | udata/core/organization/api.py, udata/core/organization/notifications.py, udata/tests/api/test_organizations_api.py (+1 more) |
| 31 | **REVIEW** | `b42a9aca5` | fix(harvest): csw-* harvesters fail on some XML comments (#3758) | udata/harvest/backends/dcat.py, udata/harvest/tests/test_dcat_backend.py |
| 32 | **REVIEW** | `adf0b8554` | feat: use volumes for all services (#3761) | docker-compose.yml |
| 33 | **HOTSPOT** | `a4e93a96d` | feat: ask user password rotation via API (#3762) | udata/core/user/api.py, udata/core/user/api_fields.py, udata/core/user/commands.py (+2 more) |
| 34 | **REVIEW** | `95abdbc18` | Bump version 16.4.0 | CHANGELOG.md |
| 35 | **REVIEW** | `ddd7885ed` | feat: send notifications for a new reuse and dataservice on one of your datasets (#3763) | udata/core/dataservices/notifications.py, udata/core/owned.py, udata/core/reuse/notifications.py (+5 more) |
| 36 | **REVIEW** | `3c1066a5e` | feat: upgrade dependencies | uv.lock |
| 37 | **REVIEW** | `1c3e87e39` | fix(deps): update dependency importlib-resources to v7 (#3747) | pyproject.toml, uv.lock |
| 38 | **REVIEW** | `ebaeabf70` | chore(deps): update dependency faker to v40 (#3742) | pyproject.toml, uv.lock |
| 39 | **REVIEW** | `f79e07b03` | chore(deps): update dependency invoke to v3 (#3744) | pyproject.toml, uv.lock |
| 40 | **REVIEW** | `c522dd740` | fix: missing last_login_at in org members response (#3766) | udata/core/user/api_fields.py, udata/core/user/models.py, udata/tests/api/test_organizations_api.py (+1 more) |
| 41 | **REVIEW** | `2ab857000` | chore(deps): update dependency faker to >=40.18, <40.19 (#3769) | pyproject.toml, uv.lock |
| 42 | **REVIEW** | `0d0307aea` | Bump version 16.5.0 | CHANGELOG.md |
| 43 | **REVIEW** | `4f5d31b37` | fix(harvest): csw-dcat harvester fails on a record parsing error (#3770) | udata/harvest/backends/base.py, udata/harvest/backends/dcat.py, udata/harvest/tests/test_dcat_backend.py |
| 44 | **REVIEW** | `0a3bbe65e` | feat(harvest): report conflicting record ownership (#3771) | udata/harvest/backends/base.py, udata/harvest/tests/test_base_backend.py |
| 45 | **REVIEW** | `b3a73c011` | fix(harvest): add missing click argument to delete command (#3774) | udata/harvest/commands.py |
| 46 | **REVIEW** | `73462ab93` | Fix/cli (#3776) | .gitignore, udata/harvest/actions.py, udata/harvest/commands.py |
| 47 | **REVIEW** | `6b4f02b12` | Enhance/doc (#3778) | docs/getting-started.md, docs/harvesting.md |
| 48 | **REVIEW** | `5138653b4` | fix(harvest): normalize tag values in TagListField to match harvester input (#3782) | udata/mongo/taglist_field.py, udata/tests/dataset/test_dataset_rdf.py, udata/tests/test_tags.py |
| 49 | **REVIEW** | `7747bcfdc` | chore(deps): lock file maintenance (#3772) | uv.lock |
| 50 | **REVIEW** | `ee2dbc9a5` | fix(deps): update dependency bcrypt to v5 (#3745) | pyproject.toml, uv.lock |
| 51 | **REVIEW** | `346227bcb` | chore(deps): update dependency faker to >=40.19, <40.20 (#3786) | pyproject.toml, uv.lock |
| 52 | **HOTSPOT** | `91f344f1e` | feat: improve cors (#3781) | udata/cors.py, udata/settings.py, udata/tests/api/test_base_api.py (+1 more) |

## Summary

- SAFE:    0
- REVIEW:  44
- HOTSPOT: 8

**Legend:**
- **SAFE** — only touches `core/badges/`, `core/jobs/`, `core/followers/`, `core/tags/`.
- **HOTSPOT** — touches a known fork customization (SAML, PT harvesters, dataset/site/org/user API, settings, translations). Manual review required.
- **REVIEW** — anything else. Likely safe but read the diff.
