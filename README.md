# Vault JWT Secrets Plugin

Fetch [HashiCorp Vault](https://www.vaultproject.io/) secrets inside Jenkins pipelines using
**short-lived, per-build JWTs** instead of a long-lived AppRole or token stored in Jenkins. It is a
Jenkins-native reimagining of GitLab CI's [`id_tokens` + `secrets:vault:`](https://docs.gitlab.com/ci/secrets/hashicorp_vault/)
model.

Each build mints its own signed ID token (via the [OpenID Connect Provider](https://plugins.jenkins.io/oidc-provider/)
plugin). Vault verifies that token against Jenkins' OIDC discovery endpoint and decides — through its own
JWT auth role (`bound_audiences`, `bound_claims`) — which builds may read which secrets. **No standing Vault
credential is ever stored in Jenkins.** Secret values are masked in the console log.

## Why not the existing hashicorp-vault-plugin?

That plugin authenticates with static credentials (AppRole role-id/secret-id, tokens). Those are standing
secrets: anyone who compromises Jenkins gets them. This plugin issues a fresh JWT scoped to a single build,
so a leak is short-lived and authorization is enforced per-job on the Vault side.

## Requirements

- Jenkins 2.541.3+
- [OpenID Connect Provider](https://plugins.jenkins.io/oidc-provider/) plugin (installed automatically as a
  dependency)
- A HashiCorp Vault server whose JWT auth method can reach your Jenkins OIDC discovery endpoint at
  `${JENKINS_URL}oidc/.well-known/openid-configuration`
- **The Jenkins root URL must be set and reachable from Vault** (Manage Jenkins » System » Jenkins URL)

## Installation

The plugin is not in the Jenkins update center yet, so install the `.hpi` directly:

1. Download `vault-jwt-secrets.hpi` from this repository's **Releases** page (or build it — see
   [Building](#building)).
2. **Manage Jenkins » Plugins » Advanced settings » Deploy Plugin**, choose the file, and restart when
   prompted. Jenkins pulls the OpenID Connect Provider dependency from the update center automatically.

For image-based controllers, drop the file into the plugins directory instead. Dependencies are not
resolved for a file placed there, so install them explicitly (this mirrors [`e2e/Dockerfile`](e2e/Dockerfile)):

```dockerfile
FROM jenkins/jenkins:lts-jdk17
RUN jenkins-plugin-cli --plugins oidc-provider workflow-aggregator \
    credentials credentials-binding plain-credentials cloudbees-folder
ADD --chown=jenkins:jenkins \
    https://github.com/<owner>/vault-jwt-secrets-plugin/releases/download/v<version>/vault-jwt-secrets.hpi \
    /usr/share/jenkins/ref/plugins/vault-jwt-secrets.jpi
```

## Pipeline usage

### GitLab-style block step

```groovy
withVaultJwtSecrets(role: 'myapp-deploy', secrets: [
    vaultSecret(path: 'production/db/password@ops', var: 'DB_PASSWORD'),
    vaultSecret(path: 'production/tls/cert@ops',    var: 'TLS_CERT_FILE', type: 'file'),
]) {
    sh 'deploy.sh'   // $DB_PASSWORD is set only inside this block and masked in the log
}
```

- `path` uses GitLab notation `path/to/secret@mount`; `@mount` is optional and defaults to the configured
  default mount. As in GitLab, the last segment names the **field**, so
  `production/db/password@ops` reads the `password` key of `ops/data/production/db` (KV v2). Pass
  `field: 'password'` explicitly instead if a path segment would be ambiguous.
- `type: 'env'` (default) binds the value to an environment variable; `type: 'file'` writes it to a
  temporary 0600 file (deleted when the block ends) and binds the file path.
- `role`, `vaultUrl`, `authPath`, `namespace`, `audience` are optional overrides of the folder/global config.

Also works in Declarative pipelines as a wrapper in `options`:

```groovy
pipeline {
  agent any
  options {
    withVaultJwtSecrets(secrets: [vaultSecret(path: 'production/db/password@ops', var: 'DB_PASSWORD')])
  }
  stages { stage('deploy') { steps { sh 'deploy.sh' } } }
}
```

### The raw token — `withVaultJwtToken`

Sometimes you want the JWT itself: to drive `vault login` by hand, to call the Vault API from a script, or
to authenticate to some *other* service that trusts this Jenkins as an OIDC issuer. This is the direct
analog of GitLab's `id_tokens:`:

```groovy
withVaultJwtToken(audience: 'https://vault.corp', variable: 'VAULT_ID_TOKEN') {
    sh '''
      vault write -field=token auth/jwt/login role=myapp-deploy jwt="$VAULT_ID_TOKEN" > .vault-token
      vault kv get -field=password ops/production/db
    '''
}
```

- `variable` defaults to `VAULT_ID_TOKEN`. The value is masked in the console log and unset when the block
  ends.
- `audience` defaults to the Vault URL resolved from the folder/global config, so inside a configured
  folder `withVaultJwtToken { ... }` with no arguments already does the right thing. Pass it explicitly for
  a non-Vault audience — one signing keypair (JWKS `kid`) is provisioned per distinct audience.
- The token carries the same claims as the ones `withVaultJwtSecrets` uses (see below), so the same Vault
  role authorizes both paths.

### Configuring with Jenkins environment variables

GitLab configures Vault entirely through CI/CD variables. **The same four variable names work here**, at any
level Jenkins can set an environment variable — job `environment {}`, a `withEnv` block, folder or global
env properties:

| Variable | Meaning |
|---|---|
| `VAULT_SERVER_URL` | Vault base URL (also the default `aud`) |
| `VAULT_AUTH_ROLE` | JWT auth role to assume |
| `VAULT_AUTH_PATH` | JWT auth mount (default `jwt`) |
| `VAULT_NAMESPACE` | Vault Enterprise namespace |

```groovy
pipeline {
  agent any
  environment {
    VAULT_SERVER_URL = 'https://vault.corp'
    VAULT_AUTH_ROLE  = 'myapp-deploy'
  }
  stages {
    stage('deploy') {
      steps {
        // no connection arguments at all — exactly like GitLab's `secrets:` block
        withVaultJwtSecrets(secrets: [vaultSecret(path: 'production/db/password@ops', var: 'DB_PASSWORD')]) {
          sh 'deploy.sh'
        }
      }
    }
  }
}
```

Additionally, **every** setting (`audience`, `vaultUrl`, `role`, `authPath`, `namespace`, `defaultMount`) is
`${VAR}`-expanded against the build environment wherever it is configured — global, folder, step, or
credential. So a single folder property can serve many jobs:

```groovy
// folder sets role = '${TEAM}-deploy'; each job just defines TEAM
withVaultJwtSecrets(audience: '${VAULT_SERVER_URL}', secrets: [ /* ... */ ]) { sh 'deploy.sh' }
```

Use **single quotes** in Groovy so Jenkins — not Groovy — does the substitution. Unknown variables are left
untouched rather than blanked, so a typo fails loudly instead of silently reading the wrong path.

### As a credential

Define a **Vault JWT secret** credential (path + field). Any build that uses it resolves the value live
through a per-build JWT:

```groovy
withCredentials([string(credentialsId: 'prod-db-password', variable: 'DB_PASSWORD')]) {
    sh 'deploy.sh'
}
```

## Configuration

Vault coordinates (`vaultUrl`, `role`, `authPath`, `namespace`, `defaultMount`, `audience`) typically differ
**per team / per namespace / per role**, so configure them where that variation lives — on the **folder** or
in the **pipeline** — not as one instance-wide value. Settings layer
**global → folder → `VAULT_*` environment variables → step/credential arguments**, and the innermost
non-empty value wins. Only `vaultUrl` and `role` are required (after merging).

### Folder level — the recommended home (per team / per namespace)

Give each team a folder and set its Vault coordinates once, under
**Folder » Configure » Vault JWT Secrets overrides**. Every job inside inherits them; nested folders
override their parents. This is where stable, team-wide values belong:

```
team-a/          folder: vaultUrl=https://vault.corp, namespace=team-a, role=team-a-ci, authPath=jenkins
  ├── deploy     (inherits all of team-a's Vault coordinates)
  └── build
team-b/          folder: namespace=team-b, role=team-b-ci
  └── deploy
```

### Pipeline level — per job / per role

Declare (or override just the differing field, usually `role`) right in the `Jenkinsfile`:

```groovy
withVaultJwtSecrets(
    vaultUrl:  'https://vault.corp',   // omit any field to inherit it from the folder
    namespace: 'team-a',               // Vault Enterprise namespace
    role:      'backend-deploy',       // the role this specific job assumes
    secrets: [ vaultSecret(path: 'prod/db@secret', field: 'password', var: 'DB_PASSWORD') ]
) {
    sh 'deploy.sh'
}
```

### Global level — optional instance-wide default

**Manage Jenkins » System » Vault JWT Secrets** (JCasC symbol `vaultJwtSecrets`) is only a *fallback* for
values common to the whole controller. Leave it empty if teams differ. When used:

```yaml
unclassified:
  vaultJwtSecrets:
    vaultUrl: "https://vault.example.com"
    authPath: "jwt"
    role: "jenkins-default"
    defaultMount: "secret"
```

## Vault-side setup

```sh
# 1. Enable and configure the JWT auth method to trust Jenkins' OIDC issuer
vault auth enable jwt
vault write auth/jwt/config \
    oidc_discovery_url="https://jenkins.example.com/oidc" \
    bound_issuer="https://jenkins.example.com/oidc"

# 2. A policy granting least-privilege read on the secrets a job needs
vault policy write jenkins-myapp - <<EOF
path "ops/data/production/db" { capabilities = ["read"] }
EOF

# 3. A role bound to BOTH the audience and the job identity (sub = job URL)
vault write auth/jwt/role/myapp-deploy \
    role_type="jwt" \
    user_claim="sub" \
    bound_audiences="https://vault.example.com" \
    bound_claims_type="glob" \
    bound_claims='{"sub":"https://jenkins.example.com/job/myapp/*"}' \
    token_policies="jenkins-myapp" \
    token_ttl="60s" \
    token_num_uses=3
```

### Bootstrapping the issuer (read before step 1)

Jenkins only serves `/oidc/.well-known/openid-configuration` and `/oidc/jwks` once at least one id-token
credential exists, and this plugin auto-provisions that credential on the **first build** that needs it. Vault,
however, fetches `oidc_discovery_url` when you write `auth/jwt/config` and refuses the write if it is not
reachable. So on a fresh Jenkins, publish the issuer first — any one of:

- **Manage Jenkins » System » Vault JWT Secrets**: enter the Vault URL and any role name and click
  **Test connection**. The JWT login will fail (Vault is not configured yet) but the id-token credential is
  provisioned as a side effect. You can clear the fields afterwards if you configure per folder.
- Run any pipeline that calls `withVaultJwtSecrets` / `withVaultJwtToken` once; it fails at the Vault login
  for the same reason, but leaves the issuer published.
- Script console: `io.jenkins.plugins.vault_jwt_secrets.idtoken.IdTokenSupplier.getOrCreateIdTokenCredentials('https://vault.example.com')`
  (this is what the e2e harness does).

Then verify from the Vault host — no authentication is required, the endpoints are public:

```sh
curl -s https://jenkins.example.com/oidc/.well-known/openid-configuration   # must list "jwks_uri"
curl -s https://jenkins.example.com/oidc/jwks                               # one key per audience
```

Things that make Vault reject the token even when discovery works: `bound_issuer` must equal the Jenkins
root URL + `oidc` exactly (scheme, host, port, no trailing slash); `bound_audiences` must equal the plugin's
`vaultUrl` / `audience` exactly as configured; if Jenkins uses a private CA, pass it via
`oidc_discovery_ca_pem`; a reverse proxy in front of Jenkins must let `/oidc/*` through unauthenticated.

### JWT claims available for `bound_claims`

Besides the standard `sub` = job URL, `aud` = Vault URL, and `iss` = `${JENKINS_URL}oidc`, the plugin
enriches each build token with job/folder identity claims — the Jenkins analog of GitLab's
`project_path` / `namespace_path` — so Vault roles can authorize on them:

| Claim | Value | Example |
|---|---|---|
| `sub` | job URL | `https://jenkins.example.com/job/team-a/job/backend/job/deploy/` |
| `job_path` | full job name incl. folders | `team-a/backend/deploy` |
| `folder_path` | containing folder (empty at root) | `team-a/backend` |
| `job_name` | leaf job name | `deploy` |
| `job_url` | job URL | `.../job/team-a/job/backend/job/deploy/` |
| `build_url` | this build's URL | `.../job/.../deploy/42/` |
| `build_number` | build number (integer) | `42` |

These are added additively to oidc-provider's global build-claim templates (any claim name an admin
already configured is left untouched), backed by an `EnvironmentContributor` that always sets the
underlying variables so token minting never fails on an unsubstituted claim. Example — bind a role to a
whole folder:

```sh
vault write auth/jwt/role/team-a-backend \
    role_type=jwt user_claim=sub \
    bound_audiences="https://vault.example.com" \
    bound_claims_type=glob \
    bound_claims='{"folder_path":"team-a/backend"}' \
    token_policies=team-a-backend token_ttl=60s
```

### ⚠️ Security model — read this

The per-build id token is minted from an auto-provisioned, **globally-scoped** credential. As in GitLab,
**any job on this Jenkins can obtain a token with this issuer and audience.** Authorization is therefore
enforced *on the Vault side*: always restrict each role with `bound_claims` on `sub` (the job URL) — never
rely on `bound_audiences` alone. Use short `token_ttl` and small `token_num_uses` as defense in depth.

## GitLab → Jenkins mapping

| GitLab CI | This plugin |
|---|---|
| `id_tokens: { VAULT: { aud: <url> } }` | Automatic for `withVaultJwtSecrets`; `withVaultJwtToken(audience: ...)` to get the raw JWT |
| `secrets: { X: { vault: 'prod/db/password@ops', token: $VAULT } }` | `vaultSecret(path: 'prod/db/password@ops', var: 'X')` — same one-line notation, trailing segment = field |
| `VAULT_SERVER_URL` | `VAULT_SERVER_URL` (same name), or `vaultUrl` on the global/folder/step |
| `VAULT_AUTH_ROLE` | `VAULT_AUTH_ROLE` (same name), or `role` |
| `VAULT_AUTH_PATH` | `VAULT_AUTH_PATH` (same name), or `authPath` (default `jwt`) |
| `VAULT_NAMESPACE` | `VAULT_NAMESPACE` (same name), or `namespace` |
| `file: false` (default env) | `type: 'env'` (default) |
| file-type secret | `type: 'file'` |

## End-to-end test with Docker

`e2e/run.sh` builds the plugin, starts dockerized Jenkins + Vault, and runs a seeded pipeline against real
containers. It models the real-world setup: **no global Vault config** — a `team-a` folder owns its Vault
coordinates, the pipeline just lists the secrets it wants, and the Vault role authorizes the whole folder
via the `folder_path` claim. The pipeline also exercises `withVaultJwtToken` — logging into Vault by hand
with the raw JWT and an env-var-derived audience. It asserts the build succeeds and that every secret, and
the token itself, is masked. `KEEP_UP=1 bash e2e/run.sh` leaves the stack running for manual inspection. See
[`e2e/README.md`](e2e/README.md).

## Building

No local JDK or Maven required — `build.sh` compiles and tests inside a throwaway Maven+JDK17 Docker
container (the Maven repo is cached in the `vjs-m2` Docker volume, and any `.hpi` is copied back to
`./target`):

```sh
./build.sh                       # mvn verify (tests + spotless + spotbugs + package)
./build.sh -DskipTests package   # just build the .hpi
```

If you do have a JDK 17 + Maven toolchain, `mvn clean verify` / `mvn hpi:run` work directly.

## Releasing

Versions come from git tags. Local builds are always `999999-SNAPSHOT`; pushing a tag `vX.Y.Z` makes the
`Release` GitHub Actions workflow run the full `mvn verify` as version `X.Y.Z` and attach the `.hpi` to a
GitHub release with generated notes:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

To produce the same versioned artifact locally: `./build.sh -Dchangelist=0.1.0 verify`.

## License

MIT
