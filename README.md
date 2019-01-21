# SecretUpdater

## Purpose

This app acts as the glue between Confidant and Kubernetes.

It receives a webhook from Confidant upon changes to credentials or services, and pulls the appropriate secrets out of Confidant and places them into Kubernetes as Secrets.

## Configuration

### Confidant

You may specify `secret-name` in a credential's metadata section, to have the Secret name custom defined to be the value you select.

This is useful if your helm chart defines the expected secret name based on the chart name, but you have several apps using the chart, or different environments needing different Credential values in the same-named Secret.

### Kubernetes

You may set an annotation on a Deployment, to avoid the automatic rolling update that this app defaults to triggering.

The annotation goes in `metadata.annotations`, and needs the be called `secretupdater.ffx.io/skip_reload`, with any non-false value.
