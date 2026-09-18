FROM jenkins/jenkins:2.541.3-lts-jdk17

USER root
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
USER jenkins

# Install the plugin under test plus its runtime companions.
COPY --chown=jenkins:jenkins target/*.hpi /usr/share/jenkins/ref/plugins/vault-jwt-secrets.jpi
RUN jenkins-plugin-cli --plugins \
    oidc-provider:212.v7657c4d7b_29f \
    configuration-as-code \
    workflow-aggregator \
    job-dsl \
    credentials \
    credentials-binding \
    plain-credentials \
    cloudbees-folder

COPY --chown=jenkins:jenkins casc.yaml /var/jenkins_home/casc.yaml

USER root
COPY manual-vault-login.sh /usr/local/bin/manual-vault-login.sh
RUN chmod 0755 /usr/local/bin/manual-vault-login.sh
USER jenkins

ENV JENKINS_OPTS="--prefix="
