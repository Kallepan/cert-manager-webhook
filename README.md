# Cert Manager Webhook

## Overview

This is a webhook for the cert-manager project that allows for the creation of certificates using the [ACME protocol](https://tools.ietf.org/html/rfc8555).

## Tests

To run the tests, execute the following command:

```bash
$ make test
```


## Install

Create a secret in the namespace of the webhook with the following fields:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: git-solver-webhook-config
  namespace: git-solver-webhook # release namespace of the webhook
type: Opaque
data:
  GITLAB_BRANCH: ZGV2ZWxvcA==  # base64-encoded value for "develop"
  GITLAB_PATH: cGF0aC90by9yZXBv  # base64-encoded value for "path/to/repo"
  GITLAB_FILE: cmVhZG1lLnR4dA==  # base64-encoded value for "readme.txt"
  GITLAB_TOKEN: c2VjcmV0LXRva2Vu  # base64-encoded value for "secret-token"
  GITLAB_URL: aHR0cHM6Ly9naXRsYWIuY29t  # base64-encoded value for "https://gitlab.com"
```

Base64 encoded values can be generated using the following command:

```bash
$ echo -n "value" | base64
```

Adjust the `values.yaml` file to match the secret name and namespace. Then, deploy the webhook using helm:

```bash
$ helm install git-solver-webhook ./deploy/git-solver-webhook
```
`
## Build

```
$ IMAGE_NAME=docker.io/kallepan/git-solver-webhook IMAGE_TAG=0.0.1 make build
````