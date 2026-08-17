# Upstream sync classification — `origin/main..v16.1.0`

Total commits: **4**

| # | Class | SHA | Subject | Files touched |
|---|---|---|---|---|
| 1 | **HOTSPOT** | `ddaf546eb` | chore: add access_type filter on list api endpoints and rdf catalogs (#3711) | udata/core/dataservices/search.py, udata/core/dataset/api.py, udata/core/organization/api.py (+4 more) |
| 2 | **REVIEW** | `829a4f2a8` | feat: moderation dashboard improvements (#3713) | udata/core/discussions/api.py, udata/core/discussions/models.py, udata/core/reports/models.py (+4 more) |
| 3 | **REVIEW** | `bc75acae9` | fix: duplicate dataset in test (#3715) | udata/tests/api/test_datasets_api.py |
| 4 | **REVIEW** | `8d84cef74` | Bump version 16.1.0 | CHANGELOG.md |

## Summary

- SAFE:    0
- REVIEW:  3
- HOTSPOT: 1

**Legend:**
- **SAFE** — only touches `core/badges/`, `core/jobs/`, `core/followers/`, `core/tags/`.
- **HOTSPOT** — touches a known fork customization (SAML, PT harvesters, dataset/site/org/user API, settings, translations). Manual review required.
- **REVIEW** — anything else. Likely safe but read the diff.
