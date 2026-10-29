# MLflow with Keycloak SSO

This fork adds Keycloak OpenID Connect login to MLflow and uses MLflow's RBAC store for authorization. Keycloak client roles and groups determine which MLflow roles a user receives at sign-in. MLflow keeps the role definitions and resource permissions; Keycloak manages membership. This is a source checkout of MLflow, so build the UI before starting the server.

## Changes in this fork

| Path | Change |
| --- | --- |
| `mlflow/server/auth/keycloak.py` | OpenID Connect authorization code flow with PKCE, token verification, login/logout routes, Keycloak user provisioning, client/realm/group role mapping, and role reconciliation. |
| `mlflow/server/auth/keycloak_auth.ini` | Keycloak auth configuration, default `DENY`, and local auth database URI. |
| `mlflow/server/auth/__init__.py` | Registers the Keycloak routes, protects the auth APIs, blocks local edits to Keycloak users, and exposes current user, roles, and display names to the UI. |
| `mlflow/server/auth/entities.py`, `mlflow/server/auth/db/models.py`, `mlflow/server/auth/sqlalchemy_store.py` | Persist a human-readable Keycloak email/username alongside the stable `keycloak:<sub>` user key. |
| `mlflow/server/auth/db/migrations/versions/b4c17a0e3d92_add_user_display_name.py` | Migrates existing auth databases to add the optional display-name column. |
| `mlflow/server/__init__.py`, `mlflow/server/handlers.py` | Integrates Keycloak auth mode with server setup and server-info. |
| `mlflow/server/fastapi_security.py` | Preserves multiple `Set-Cookie` headers during the login callback. |
| `mlflow/server/js/src/MlflowRouter.tsx` | Shows the Keycloak sign-in screen when unauthenticated and gates the authenticated UI. |
| `mlflow/server/js/src/common/components/MlflowSidebar.tsx` | Adds Keycloak logout and shows **Manage** only to platform admins. |
| `mlflow/server/js/src/account/AccountPage.tsx`, `mlflow/server/js/src/account/types.ts` | Shows the current user's display name and Keycloak auth state. |
| `mlflow/server/js/src/admin/pages/AdminPage.tsx`, `mlflow/server/js/src/admin/pages/UserDetailPage.tsx` | Shows Keycloak email/username in the Users page and hides local user-management controls in Keycloak mode. Internal account links still use the stable user key. |
| `mlflow/server/js/src/experiment-tracking/hooks/useServerInfo.tsx` | Types the server's auth-mode response. |
| `pyproject.toml`, `dev/pyproject.py`, `uv.lock` | Adds PyJWT with crypto support to the auth extra and packages the Keycloak config file. |
| `mlflow/server/js/yarn.lock` | Lockfile refreshed during the frontend dependency install. |
| `docs/docs/self-hosting/security/keycloak-sso.mdx`, `docs/docs/self-hosting/security/sso.mdx`, `docs/sidebarsSelfHosting.ts` | Adds and links the Keycloak setup documentation. |
| `tests/server/auth/test_keycloak.py`, `tests/server/auth/test_sqlalchemy_store.py`, `tests/server/test_security.py` | Covers the OIDC flow, role sync, display-name persistence, and multiple cookie headers. |
| `.gitignore` | Excludes the local Keycloak auth database alongside the already ignored `.env`, `.venv`, `node_modules`, and UI build. |

The built-in `admin` row is the local bootstrap account in the auth database. Keycloak users have separate stable IDs. A Keycloak user becomes a platform admin only when their ID token contains the configured admin **client role**. Platform admins bypass resource `DENY`, so test deny roles with a non-admin user.

## After cloning: Windows PowerShell local setup

Run these commands from the **repository root** unless a step says otherwise. The UI is served by MLflow at `http://localhost:5000`; port 3000 is only for an optional React development server.

### 1. Prerequisites

- Git and Docker Desktop (for your separately managed Keycloak container).
- Python 3.12 is a good local choice; this repository declares Python `>=3.10`. The setup here was exercised with Python 3.12.6.
- Node.js **24.14.x** (the frontend's declared engine). The frontend uses the checked-in **Yarn 4.12.0** release, so no global Yarn install is needed. A local build also succeeded with Node 22.19.0, but use the declared version for a clean setup.

```powershell
git clone --recurse-submodules <YOUR_NEW_REPOSITORY_URL>
cd <CLONED_REPOSITORY_DIRECTORY>
py -3.12 --version
node --version
```

### 2. Set up Keycloak

Start your Keycloak container separately and verify `http://localhost:8080/realms/mlflow/.well-known/openid-configuration` opens. Create realm `mlflow` and a **confidential OpenID Connect client** with client ID `mlflow` and the authorization code flow enabled. Configure:

- Valid redirect URI: `http://localhost:5000/oauth/keycloak/callback`
- Valid post-logout redirect URI: `http://localhost:5000/`
- Web origin: `http://localhost:5000`
- Client role `mlflow-super-admin`, assigned only to platform admins.
- Client roles mapper with **Add to ID token** enabled, so `resource_access.mlflow.roles` contains the client roles. Include the `email` scope or a `preferred_username` claim for readable names.

Create at least one Keycloak user and assign `mlflow-super-admin` to that user. Use other client roles for regular MLflow role mappings. Do not assign the admin role to users testing resource restrictions.

### 3. Install the Python backend

From the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[auth]"
```

### 4. Configure local secrets

Create `.env` in the repository root. It is ignored by Git. Generate two independent random values with `.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"` and place them in the two secret fields below. Copy the client secret from Keycloak. Replace the example values as needed:

```dotenv
MLFLOW_AUTH_CONFIG_PATH=mlflow/server/auth/keycloak_auth.ini
MLFLOW_FLASK_SERVER_SECRET_KEY=<RANDOM_SECRET_1>
MLFLOW_AUTH_ADMIN_PASSWORD=<RANDOM_SECRET_2>
MLFLOW_KEYCLOAK_ISSUER=http://localhost:8080/realms/mlflow
MLFLOW_KEYCLOAK_CLIENT_ID=mlflow
MLFLOW_KEYCLOAK_CLIENT_SECRET=<KEYCLOAK_CLIENT_SECRET>
MLFLOW_KEYCLOAK_PUBLIC_URL=http://localhost:5000
MLFLOW_KEYCLOAK_ADMIN_ROLE=client:mlflow-super-admin
MLFLOW_KEYCLOAK_ROLE_MAP={}
```

For a Keycloak client role named `deny_role`, create an MLflow RBAC role named `keycloak:deny_role` and set `MLFLOW_KEYCLOAK_ROLE_MAP={"client:deny_role":"keycloak:deny_role"}`. The `keycloak:` prefix is required for the login sync to remove that assignment when it is removed in Keycloak. Define the role's resource permissions in MLflow. Role changes sync at the user's next sign-in. Keep `.env`, the auth database, and client secrets out of Git.

Because the auth database is local and ignored, a fresh clone has no custom MLflow RBAC roles or permission definitions. After the first admin login, recreate roles such as `keycloak:deny_role` and their resource permissions in **Manage** before assigning them through Keycloak.

### 5. Install and build the frontend

From the repository root:

```powershell
cd mlflow/server/js
node .\yarn\releases\yarn-4.12.0.cjs --version
node .\yarn\releases\yarn-4.12.0.cjs install --immutable
node .\yarn\releases\yarn-4.12.0.cjs build
cd ../../..
```

If `node_modules` already exists, the install step can reuse it. The resulting `mlflow/server/js/build` directory is ignored by Git and served by the MLflow server.

### 6. Start MLflow

From the repository root, with Keycloak running:

```powershell
.\.venv\Scripts\python.exe -m mlflow --env-file .env server --app-name basic-auth --host 127.0.0.1 --port 5000
```

Open `http://localhost:5000` and choose **Sign in with Keycloak**. After signing in, `/ajax-api/2.0/mlflow/users/current` shows the user and `is_admin`. The first start creates local SQLite files (`mlflow.db` and `keycloak_auth.db`); these are ignored by Git. Restart MLflow and sign in again after changing environment variables or Keycloak client roles.

## Push to your new repository

The original checkout's `origin` points to `https://github.com/mlflow/mlflow.git`. After creating your own empty repository, run from the repository root:

```powershell
git remote rename origin upstream
git remote add origin <YOUR_NEW_REPOSITORY_URL>
git push -u origin HEAD:main
```

Review `git status --short` before committing. `.venv`, `node_modules`, `.env`, local databases, and the frontend build must stay untracked. Do not push to the upstream MLflow remote.
