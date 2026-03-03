# Análise de Hierarquia de Utilizadores - udata-pt

Mapeamento completo das funcionalidades por nível de utilizador, baseado na análise do código.

---

## 1. User Não Logado (Anónimo)

| Funcionalidade | Acesso |
|---|---|
| Ver datasets públicos | Sim |
| Ver reuses públicos | Sim |
| Ver organizações | Sim |
| Ver discussões | Sim |
| Ver posts/artigos publicados | Sim |
| Ver topics | Sim |
| Ver dataservices públicos | Sim |
| Ver datasets/recursos **privados** | **Não** |
| Criar/editar qualquer conteúdo | **Não** |
| Participar em discussões | **Não** |
| Upload de ficheiros | **Não** |
| Aceder ao backoffice/admin | **Não** |

> **Mecanismo**: `OwnableReadPermission` em `udata/core/dataset/permissions.py` - se o objeto não é privado, qualquer pessoa pode ler. `visible_by_user()` em `udata/core/owned.py` retorna apenas objetos públicos para anónimos.

---

## 2. User Registado/Logado (perfil pessoal)

| Funcionalidade | Acesso |
|---|---|
| Editar o próprio perfil | Sim (`UserEditPermission`) |
| Criar datasets próprios | Sim (fica como `owner`) |
| Editar/eliminar datasets **próprios** | Sim (`DatasetEditPermission` via `UserNeed`) |
| Criar/editar/eliminar resources nos seus datasets | Sim (`ResourceEditPermission`) |
| Upload de ficheiros | Sim (`@login_required` em `storages/views.py`) |
| Criar reuses próprias | Sim |
| Editar/eliminar reuses **próprias** | Sim (`ReuseEditPermission`) |
| Criar topics próprios | Sim (`@apiv2.secure` em `topic/apiv2.py`) |
| Editar/eliminar topics **próprios** | Sim (`TopicEditPermission`) |
| Criar dataservices próprios | Sim |
| Editar/eliminar dataservices **próprios** | Sim (`DataserviceEditPermission`) |
| Criar páginas | Sim (`@api.secure` em `pages/api.py:25`) |
| Participar em discussões (criar/comentar) | Sim |
| Editar/eliminar as **próprias** mensagens em discussões | Sim (`DiscussionMessagePermission`) |
| Pedir adesão a uma organização | Sim (`MembershipRequest`) |
| Criar/editar posts/artigos | **Não** (requer `admin_permission`) |
| Publicar posts | **Não** |
| Atribuir badges | **Não** |
| Gerir harvesters | **Não** (sem organização) |
| Editar conteúdo de **outros** utilizadores | **Não** |
| Listar páginas (GET /pages/) | **Não** (requer `admin_permission` em `pages/api.py:17`) |

> **Mecanismo**: `OwnablePermission` em `dataset/permissions.py` verifica `UserNeed(obj.owner.fs_uniquifier)` - apenas o owner tem permissão.

---

## 3. User Registado + Membro de Organização

Existem **dois sub-níveis** dentro da organização (`udata/core/organization/constants.py`):

### 3a. Editor de Organização (role por defeito)

| Funcionalidade | Acesso |
|---|---|
| Tudo do nível 2 (user logado) | Sim |
| Editar datasets da **organização** | Sim (`OrganizationEditorNeed`) |
| Editar/criar resources nos datasets da org | Sim |
| Editar reuses da **organização** | Sim |
| Editar topics da **organização** | Sim |
| Editar dataservices da **organização** | Sim |
| Editar páginas da **organização** | Sim |
| Ver conteúdo **privado** da organização | Sim (`OrganizationPrivatePermission`) |
| Preview de harvesters | Sim (`HarvestSourcePermission`) |
| Editar/eliminar/correr harvesters | **Não** (requer `HarvestSourceAdminPermission`) |
| Editar definições da organização | **Não** (requer `EditOrganizationPermission` = org admin) |
| Gerir membros da organização | **Não** |
| Aceitar/recusar pedidos de adesão | **Não** |
| Atribuir badges | **Não** |
| Iniciar transferências | **Não** (requer org admin) |

### 3b. Admin de Organização

| Funcionalidade | Acesso |
|---|---|
| Tudo do Editor de organização | Sim |
| Editar definições da organização (nome, descrição, logo) | Sim (`EditOrganizationPermission`) |
| Gerir membros (adicionar/remover/alterar role) | Sim (`EditOrganizationPermission` em `organization/apiv2.py`) |
| Aceitar/recusar pedidos de adesão | Sim |
| Editar/eliminar/correr harvesters | Sim (`HarvestSourceAdminPermission`) |
| Agendar harvesters | Sim |
| Atribuir badges (na organização) | Sim (`BadgePermission`) |
| Iniciar transferências de assets | Sim (`TransferPermission`) |
| Responder a pedidos de transferência | Sim (`TransferResponsePermission`) |
| Criar/publicar posts/artigos | **Não** (requer sysadmin) |

> **Mecanismo**: Quando o user faz login, o signal `identity_loaded` em `organization/permissions.py` injeta `OrganizationNeed(role, org_id)` para cada organização a que pertence.

---

## 4. Super Admin (sysadmin)

| Funcionalidade | Acesso |
|---|---|
| **Tudo** dos níveis anteriores | Sim |
| Bypass de **todas** as verificações de permissão | Sim |
| Criar/editar/publicar/eliminar posts/artigos | Sim (`admin_permission` em `post/api.py`) |
| Listar todas as páginas | Sim (`admin_permission` em `pages/api.py`) |
| Ver **todos** datasets (incluindo privados) | Sim (`visible_by_user` retorna tudo) |
| Editar qualquer dataset/reuse/topic de qualquer user/org | Sim (via `RoleNeed("admin")` automático) |
| Gerir qualquer organização | Sim |
| Gerir qualquer harvester | Sim |
| Atribuir/remover badges em qualquer entidade | Sim |
| Aceitar/recusar transferências | Sim |
| Funcionar em READ_ONLY_MODE | Sim (bypass em `api/__init__.py:68-77`) |
| OAuth2 scope "admin" | Sim |

> **Mecanismo**: A classe base `Permission` em `udata/auth/__init__.py` adiciona automaticamente `RoleNeed("admin")` a **todas** as permissões. Isso significa que o sysadmin (`user.has_role("admin")`) passa em qualquer verificação de permissão do sistema.

---

## Resumo Visual

```
                    ┌─────────────────────────────┐
                    │       SUPER ADMIN            │
                    │  Bypass total de permissões  │
                    │  Posts, Pages, READ_ONLY     │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │    ORG ADMIN                 │
                    │  Gestão org + membros        │
                    │  Harvesters, Badges          │
                    │  Transferências              │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │    ORG EDITOR                │
                    │  Edit conteúdo da org        │
                    │  Ver privados da org         │
                    │  Preview harvesters          │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │    USER LOGADO               │
                    │  CRUD conteúdo próprio       │
                    │  Discussões, Upload          │
                    │  Pedir adesão a orgs         │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │    USER ANÓNIMO              │
                    │  Apenas leitura pública      │
                    └─────────────────────────────┘
```

---

## Ficheiros-chave de referência

| Componente | Ficheiro |
|---|---|
| Roles do sistema | `udata/core/user/permissions.py` |
| Roles de organização | `udata/core/organization/constants.py` |
| Base Permission (admin bypass) | `udata/auth/__init__.py` |
| Dataset permissions | `udata/core/dataset/permissions.py` |
| Post permissions (admin only) | `udata/core/post/api.py` |
| Harvest permissions | `udata/harvest/permissions.py` |
| Visibilidade por user | `udata/core/owned.py` (método `visible_by_user`) |
| Injeção de org needs | `udata/core/organization/permissions.py` |
