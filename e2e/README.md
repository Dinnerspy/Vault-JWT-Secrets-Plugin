# End-to-end test (dockerized Jenkins + Vault)

Spins up real containers and proves the whole flow: a build mints a JWT via oidc-provider, Vault verifies it
against the Jenkins OIDC discovery endpoint, the plugin reads a KV v2 secret, and the value is masked in the
log.

## Run

```sh
./e2e/run.sh
```

It will:

1. `mvn package` the plugin (skip with `SKIP_BUILD=1` if `target/*.hpi` already exists).
2. `docker compose up` a `hashicorp/vault` dev server and a Jenkins built from `Dockerfile` (this plugin +
   oidc-provider + JCasC in `casc.yaml`, which seeds global config, a `vaultJwtSecret` credential, and the
   `vault-e2e` pipeline).
3. Configure Vault (`vault-init.sh`): enable JWT auth trusting `http://jenkins:8080/oidc`, create role `e2e`
   bound to the job `sub` claim, seed `secret/production/db`.
4. Trigger the `vault-e2e` job and assert: build **SUCCESS**, all three secrets **masked** (`****`), and the
   raw secret values **absent** from the log.

Containers are torn down on exit. Requires Docker + Docker Compose.

## Networking note

Vault and Jenkins share a compose network, so Vault resolves the issuer at `http://jenkins:8080/oidc`. The
Jenkins root URL is set to `http://jenkins:8080/` (in `casc.yaml`) so the `iss` claim matches what Vault
expects. In production both must use HTTPS.
