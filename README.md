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

## Pipeline usage

### GitLab-style block step

```groovy
withVaultJwtSecrets(role: 'myapp-deploy', secrets: [
    vaultSecret(path: 'production/db@ops', field: 'password', var: 'DB_PASSWORD'),
    vaultSecret(path: 'production/tls@ops', field: 'cert',    var: 'TLS_CERT_FILE', type: 'file'),
]) {
    sh 'deploy.sh'   // $DB_PASSWORD is set only inside this block and masked in the log
}
```

- `path` uses GitLab notation `path/to/secret@mount`; `@mount` is optional and defaults to the configured
  default mount. `production/db@ops` reads `ops/data/production/db` (KV v2).
- `type: 'env'` (default) binds the value to an environment variable; `type: 'file'` writes it to a
  temporary 0600 file (deleted when the block ends) and binds the file path.
- `role`, `vaultUrl`, `authPath`, `namespace`, `audience` are optional overrides of the folder/global config.

Also works in Declarative pipelines as a wrapper in `options`:

```groovy
pipeline {
  agent any
  options {
    withVaultJwtSecrets(secrets: [vaultSecret(path: 'production/db@ops', field: 'password', var: 'DB_PASSWORD')])
  }
  stages { stage('deploy') { steps { sh 'deploy.sh' } } }
}
```

### As a credential

Define a **Vault JWT secret** credential (path + field). Any build that uses it resolves the value live
through a per-build JWT:

```groovy
withCredentials([string(credentialsId: 'prod-db-password', variable: 'DB_PASSWORD')]) {
    sh 'deploy.sh'
}
```

## Configuration

Settings layer **global → folder → step/credential** (inner wins):

- **Manage Jenkins » System » Vault JWT Secrets** — instance defaults (JCasC symbol `vaultJwtSecrets`).
- **Folder » Configure » Vault JWT Secrets overrides** — per-folder overrides.
- Step parameters / credential fields — most specific.

JCasC example:

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

The default id token claims (from the oidc-provider plugin) are `sub` = the job URL, `build_number`,
`aud` = the Vault URL, and `iss` = `${JENKINS_URL}oidc`.

### ⚠️ Security model — read this

The per-build id token is minted from an auto-provisioned, **globally-scoped** credential. As in GitLab,
**any job on this Jenkins can obtain a token with this issuer and audience.** Authorization is therefore
enforced *on the Vault side*: always restrict each role with `bound_claims` on `sub` (the job URL) — never
rely on `bound_audiences` alone. Use short `token_ttl` and small `token_num_uses` as defense in depth.

## GitLab → Jenkins mapping

| GitLab CI | This plugin |
|---|---|
| `id_tokens: { VAULT: { aud: <url> } }` | Automatic; `aud` defaults to the Vault URL (override with `audience`) |
| `secrets: { X: { vault: 'prod/db@ops', token: $VAULT } }` | `vaultSecret(path: 'prod/db@ops', field: '...', var: 'X')` |
| `VAULT_SERVER_URL` | `vaultUrl` (global/folder/step) |
| `VAULT_AUTH_ROLE` | `role` |
| `VAULT_AUTH_PATH` | `authPath` (default `jwt`) |
| `VAULT_NAMESPACE` | `namespace` |
| `file: false` (default env) | `type: 'env'` (default) |
| file-type secret | `type: 'file'` |

## End-to-end test with Docker

`e2e/run.sh` builds the plugin, starts dockerized Jenkins + Vault, runs a seeded pipeline, and asserts the
secret is fetched and masked. See [`e2e/README.md`](e2e/README.md).

## Building

```sh
mvn clean verify          # unit + integration tests
mvn hpi:run               # run a local Jenkins with the plugin at http://localhost:8080/jenkins/
```

## License

MIT
