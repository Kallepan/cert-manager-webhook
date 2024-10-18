# Cert Manager Webhook

## Overview

This is a webhook for the cert-manager project that allows for the creation of certificates using the [ACME protocol](https://tools.ietf.org/html/rfc8555).

## Tests

To run the tests, execute the following command:

```bash
make test
```

## Install

Create a secret in the namespace of the webhook with the following fields:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: git-solver-webhook-secret
  namespace: git-solver-webhook # release namespace of the webhook
type: Opaque
data:
  GITLAB_TARGET_BRANCH: bWFpbg==  # Source branch for the merge request
  GITLAB_BOT_COMMENT_PREFIX: U1ZD # Prefix added to the regex which finds the bot's comments
  GITLAB_BOT_BRANCH: ZGV2ZWxvcA==  # The branch where the bot will push the changes and create the merge request
  GITLAB_PATH: cGF0aC90by9yZXBv  # Path of the gitlab repository
  GITLAB_FILE: cmVhZG1lLnR4dA==  # Zone file name
  GITLAB_TOKEN: c2VjcmV0LXRva2Vu  # Gitlab token for authentication
  GITLAB_URL: aHR0cHM6Ly9naXRsYWIuY29t  # Gitlab URL
```

Base64 encoded values can be generated using the following command:

```bash
echo -n "value" | base64
```

Adjust the `values.yaml` file to match the secret name and namespace. Then, deploy the webhook using helm:

```bash
export KUBECONFIG=~/.kube/config
helm --kubeconfig $KUBECONFIG --namespace cert-manager install git-solver-webhook ./deploy/git-solver-webhook
```

## Build

```bash
IMAGE_NAME=docker.io/kallepan/git-solver-webhook IMAGE_TAG=0.0.1 make build
```
