# End-to-end test (dockerized Jenkins + Vault)

Spins up real containers and proves the whole flow: a build mints a JWT via oidc-provider, Vault verifies it
against the Jenkins OIDC discovery endpoint, the plugin reads a KV v2 secret, and the value is masked in the
log.

It is deliberately shaped like a real installation: **there is no global Vault configuration**. The `team-a`
folder owns its Vault coordinates (`vaultUrl`, `role`, `defaultMount`); the pipeline only lists the secrets
it wants; and the Vault role authorizes the whole folder through the `folder_path` claim rather than one
job's URL.

## Run

```sh
./e2e/run.sh
```

Knobs: `SKIP_BUILD=1` reuses an existing `target/*.hpi`; `KEEP_UP=1` leaves the stack running afterwards
(Jenkins on <http://localhost:18080>, `admin`/`admin`; Vault on <http://localhost:18200>, token `root`).

It will:

1. Build the plugin in a throwaway Maven container (`build.sh`).
2. `docker compose up` a `hashicorp/vault` dev server and a Jenkins built from `Dockerfile` (this plugin +
   oidc-provider + JCasC in `casc.yaml`, which seeds the `team-a` folder, the `team-a/deploy` pipeline, and a
   `vaultJwtSecret` credential). The volume is deleted first — `jenkins/jenkins` declares
   `/var/jenkins_home` as a `VOLUME`, so a stale one would shadow the freshly baked `casc.yaml`.
3. Provision the OIDC issuer. In production the first build does this by itself, but Vault validates its
   `oidc_discovery_url` at config time, so the script calls `IdTokenSupplier.getOrCreateIdTokenCredentials`
   directly to make the ordering deterministic.
4. Configure Vault (`vault-init.sh`): enable JWT auth trusting `http://jenkins:8080/oidc`, create role `e2e`
   bound to `folder_path=team-a*`, seed `secret/production/db`.
5. Trigger `team-a/deploy` and assert: build **SUCCESS**; the env, file, and credential secrets plus the raw
   id token all **masked** (`****`); the raw secret values **absent** from the log; and the `raw-token`
   stage's hand-rolled Vault login (`manual-vault-login.sh`, driven by `withVaultJwtToken` with an
   env-var-derived audience) succeeding.

Containers are torn down on exit unless `KEEP_UP=1`. Requires Docker + Docker Compose.

## Networking note

Vault and Jenkins share a compose network, so Vault resolves the issuer at `http://jenkins:8080/oidc`. The
Jenkins root URL is set to `http://jenkins:8080/` (in `casc.yaml`) so the `iss` claim matches what Vault
expects. In production both must use HTTPS.
