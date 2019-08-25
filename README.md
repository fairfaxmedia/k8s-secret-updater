# SecretUpdater

## Purpose

This app acts as the glue between Confidant and Kubernetes.

It receives a webhook from Confidant upon changes to credentials or services, and pulls the appropriate secrets out of Confidant and places them into Kubernetes as Secrets.

## Configuration

### Confidant

#### `secret-name`

You may specify `secret-name` in a credential's metadata section, to have the Secret name custom defined to be the value you select.
This is useful if your helm chart defines the expected secret name based on the chart name, but you have several apps using the chart, or different environments needing different Credential values in the same-named Secret.

#### `secret-type`

You may specify `secret-type` in a credential's metadata section to override the Secret's type from the default "Opaque".

#### `secret-case`

You may specify `secret-case` in a credential's metadata section to change the secret key name from lower to upper-case. `secret-case` is whitespace (space or newline) seperated.

#### `secret-case-regex`

You may specify `secret-case-regex` in a credential's metadata section to change any secret keys matching a specified regex to upper case. `secret-case-regex` is newline separated.

### Kubernetes

You may set an annotation on a Deployment, to avoid the automatic rolling update that this app defaults to triggering.

The annotation goes in `metadata.annotations`, and needs the be called `secretupdater.ffx.io/skip_reload`, with any non-false value.
