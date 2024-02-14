# Copyright 2019 Nine Entertainment Co.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from secretupdater import app
import re
import pykube
import datetime
import hashlib
import base64
import subprocess as sp
import json
# silence some warnings:
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

if app.config.get('AUTH_METHOD') == 'header':
    from secretupdater.headerclient import HeaderClient as ConfidantClient

    app.logger.debug('Using Header ConfidantClient - should not be done in prod!!')
else:
    from confidant_client import ConfidantClient


def process(event):
    affected_services = event.get('services') or []
    errors = []
    result_code = 200

    for service in affected_services:

        # Set up the client with correct context
        confidant = _setup_confidant_client(service=service)

        # Pull the service details from Confidant
        service_details = confidant.get_service(service=service)
        app.logger.debug(service_details)

        if service_details.get('result') and not service_details.get('service'):
            err = "Unable to pull service details for '{}'".format(service)
            app.logger.error(err)
            errors.append(err)
            result_code = 400
            break

        if service_details.get('result') and service_details['service'].get('enabled'):
            service_details = service_details['service']
            service_name = service_details['id']
            namespace = _service_to_namespace(service_name)
            credentials = service_details.get('credentials') or []

            # Find which k8s clusters the service lives on, and get their login details
            k8s_clusters = [c for c in credentials if c.get('enabled') and c.get('name').startswith('k8s-cluster-')]
            secret_collection = [s for s in credentials if s.get('enabled') and not s.get('name').startswith('k8s-cluster-')]
            app.logger.debug({"k8s_clusters": k8s_clusters, "secret_collection": secret_collection})

            # Build up the secret data.
            try:
                secrets = _parse_secret_collection(secret_collection=secret_collection, namespace=namespace)
            except BadSecretFormat as e:
                errors.append("Error in Secret data: " + str(e))
                result_code = 400
                break

            # Create a hashed value, to see if the data has changed.
            hashedval = hashlib.md5(str(repr(credentials)).encode('utf-8')).hexdigest()

            k8s_auth = _get_k8s_auth(credentials=credentials)

            for config in k8s_auth:
                app.logger.debug({"config": config})
                try:

                    kube_connection = pykube.HTTPClient(pykube.KubeConfig(config))

                    for k8s_secret in secrets.values():

                        if pykube.Secret(kube_connection, k8s_secret).exists():
                            pykube.Secret(kube_connection, k8s_secret).delete()  # We delete, rather than update(), as updates seems to keep deleted data

                        k8s_namespace = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}}
                        if not pykube.Namespace(kube_connection, k8s_namespace).exists():
                            errors.append("Creating namespace %s" % (namespace))
                            pykube.Namespace(kube_connection, k8s_namespace).create()

                        pykube.Secret(kube_connection, k8s_secret).create()

                    _trigger_deployment(kube_connection, namespace, checksum=hashedval)  # After updating secrets, we trigger a rolling update in the namespace

                except KeyError as e:
                    errors.append(str(e))
                    result_code = 500
                    app.logger.debug({"error": e})

                except NamespaceNoDeploymentError as e:
                    errors.append(str(e))
                    result_code = 200

    return {'code': result_code, 'errors': errors}


def _trigger_deployment(kube_connection, namespace, timestamp=datetime.datetime.utcnow(), checksum=None):
    res = pykube.Deployment.objects(kube_connection).filter(namespace=namespace).all()

    response = {"items": []}
    try:
        response = res.response
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            raise NamespaceNoDeploymentError("no deployments found in namespace '%s'" % (namespace))

        raise

    for deployment in response['items']:
        if 'annotations' not in deployment['spec']['template']['metadata']:
            deployment['spec']['template']['metadata']['annotations'] = {}
        if 'annotations' in deployment['metadata'] and 'secretupdater.ffx.io/skip_reload' in deployment['metadata']['annotations']:
            app.logger.debug('Skipping deployment reload due to "skip_reload" annotation')
            continue
        if checksum and 'secretupdater.ffx.io/hash' in deployment['spec']['template']['metadata']['annotations'] and deployment['spec']['template']['metadata']['annotations']['secretupdater.ffx.io/hash'] == checksum:
            app.logger.debug('Skipping deployment due to no changes')
            continue

        deployment['spec']['template']['metadata']['annotations']['secretupdater.ffx.io/last_update'] = timestamp.isoformat() + "Z"
        if checksum:
            deployment['spec']['template']['metadata']['annotations']['secretupdater.ffx.io/hash'] = checksum
        pykube.Deployment(kube_connection, deployment).update()
        app.logger.debug(deployment['spec']['template']['metadata'])


def _service_to_namespace(service_name):
    if service_name.startswith('k8s-') and not service_name.startswith('k8s-cluster-'):
        return service_name[4:]
    return service_name


def _get_credential(credential_list, credential_name):
    if credential_name in credential_list.get('credential_pairs').keys():
        return credential_list.get('credential_pairs')[credential_name]
    return None


def _setup_confidant_client(service):
    """
    Get confidant client configured to access secrets in the supplied service
    """
    auth_key = app.config.get('CONFIDANT_SERVER_AUTH_KEY')
    client = ConfidantClient(
        url=app.config.get('CONFIDANT_SERVER_URL'),
        auth_key='alias/{}'.format(auth_key),
        auth_context={
            "user_type": "service",
            "to": auth_key,
            "from": service
        },
        region=app.config.get('CONFIDANT_SERVER_AWS_REGION'),
        token_cache_file='/tmp/confidant_token',
        backoff=app.config.get('CONFIDANT_REQUEST_BACKOFF'),
        timeout=app.config.get('CONFIDANT_REQUEST_TIMEOUT'),
        retries=app.config.get('CONFIDANT_REQUEST_RETRIES')
    )
    app.logger.debug(client.config)
    return client


def _parse_secret_collection(secret_collection, namespace):
    secrets = {}

    for entry in secret_collection:
        secret = _parse_secret_entry(entry, namespace)

        if 'metadata' not in secret:
            continue
        if 'name' not in secret['metadata']:
            continue

        name = secret['metadata']['name']
        secrets[name] = secret

    return secrets


def _parse_secret_entry(entry, namespace):
    if 'secret-name' in entry.get('metadata'):
        secret_name = entry.get('metadata').get('secret-name')
    else:
        secret_name = entry.get('name')

    if 'secret-type' in entry.get('metadata'):
        secret_type = entry.get('metadata').get('secret-type')
    else:
        secret_type = 'Opaque'

    secret_pairs = entry.get('credential_pairs')

    if 'secret-case' in entry.get('metadata'):
        upper_case_creds = entry.get('metadata').get('secret-case').split()
        for key in secret_pairs:
            if key in upper_case_creds:
                val = secret_pairs[key]
                secret_pairs.pop(key)
                secret_pairs[key.upper()] = val

    if 'secret-case-regex' in entry.get('metadata'):
        upper_case_regex = entry.get('metadata').get('secret-case-regex').split("\n")
        for r in upper_case_regex:
            matching = list(filter(lambda x: re.search(r, x), secret_pairs))
            for k in matching:
                secret_pairs[k.upper()] = secret_pairs[k]
                secret_pairs.pop(k)

    for key, val in secret_pairs.items():
        if val.lower().startswith("base64:"):
            secret_pairs[key] = val[7:]

            # Check that the remainder of the string is valid base64.
            try:
                base64.b64decode(secret_pairs[key])
            except Exception:
                raise BadSecretFormat(
                    {
                        "key": key,
                        "entry": {
                            "id": entry["id"],
                            "name": entry["name"],
                            "revision": entry["revision"],
                        },
                    }
                )

        else:
            secret_pairs[key] = base64.b64encode(val.encode('utf-8')).decode('ascii')

    k8s_secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": secret_name, "namespace": namespace},
        "type": secret_type,
        "data": secret_pairs,
    }

    return k8s_secret


def _get_k8s_auth(credentials):
    k8s_auth = []
    k8s_clusters = [c for c in credentials if c.get('enabled') and c.get('name').startswith('k8s-cluster-')]

    for kube in k8s_clusters:
        id = kube.get('id')

        if _get_credential(kube, 'certificate-authority-data'):  # Assuming that if we are given the k8s CA, we're using certs
            app.logger.debug("%s: Found CA data, assuming we're using x509 for auth" % (id))
            config = _get_k8s_auth_ca(kube)

        elif _get_credential(kube, 'eks-certificate-authority-data'):
            app.logger.debug("%s: Found EKS CA data" % (id))
            config = _get_k8s_auth_eks(kube)

        elif _get_credential(kube, 'token'):
            app.logger.debug("%s: Kubernetes token provided" % (id))
            config = _get_k8s_auth_token(kube)

        elif _get_credential(kube, 'username'):
            app.logger.debug("%s: Kubernetes username/password provided" % (id))
            config = _get_k8s_auth_userpass(kube)

        k8s_auth.append(config)

    return k8s_auth


def _get_k8s_auth_ca(kube):
    return {
        "clusters": [
            {
                "name": id,
                "cluster": {
                    "server": kube.get('metadata').get('endpoint'),
                    "certificate-authority-data": _get_credential(kube, 'certificate-authority-data'),
                },
            },
        ],
        "contexts": [
            {
                "name": id,
                "context": {
                    "cluster": id,
                    "user": "admin"
                },
            }
        ],
        "current-context": id,
        "users": [
            {
                "name": "admin",
                "user": {
                    "username": _get_credential(kube, 'username'),
                    "client-certificate-data": _get_credential(kube, 'client-certificate-data'),
                    "client-key-data": _get_credential(kube, 'client-key-data'),
                },
            }
        ],
    }


def _get_k8s_auth_eks(kube):
    try:
        eks_cluster_id = re.sub(r'[^a-zA-Z0-9\s\-]', '', kube.get('metadata').get('eks-cluster-id'))
        eks_endpoint = kube.get('metadata').get('endpoint')
        eks_assume_role_arn = re.sub(r'[^a-zA-Z0-9\s\-\:\/]', '', kube.get('metadata').get('eks-assume-role-arn'))
        eks_output = sp.getoutput(f"aws eks get-token --cluster-name {eks_cluster_id} --role {eks_assume_role_arn}")
        app.logger.debug(eks_output)
    except TypeError:
        raise ClusterAttributeError("Cluster credential or metadata misconfigured or not found")

    try:
        json_token = json.loads(eks_output)
        token_data = dict(filter(lambda x: "status" in x, json_token.items()))
        token = token_data['status']['token']
        app.logger.debug(token)
    except ValueError:
        raise BadEKSToken("Unable to obtain a valid token aws-cli")

    return {
        "clusters": [
            {
                "name": eks_cluster_id,
                "cluster": {
                    "server": eks_endpoint,
                    "certificate-authority-data": _get_credential(kube, 'eks-certificate-authority-data'),
                },
            },
        ],
        "contexts": [
            {
                "name": eks_cluster_id,
                "context": {
                    "cluster": eks_cluster_id,
                    "user": "admin"
                },
            }
        ],
        "current-context": eks_cluster_id,
        "users": [
            {
                "name": "admin",
                "user": {
                    "token": token
                },
            },
        ],
    }


def _get_k8s_auth_token(kube):
    return {
        "clusters": [
            {
                "name": id,
                "cluster": {
                    "server": kube.get('metadata').get('endpoint'),
                    "insecure-skip-tls-verify": True
                },
            },
        ],
        "contexts": [
            {
                "name": id,
                "context": {
                    "cluster": id,
                    "user": "admin"
                },
            }
        ],
        "current-context": id,
        "users": [
            {
                "name": "admin",
                "user": {
                    "token": _get_credential(kube, 'token')
                }
            }
        ]
    }


def _get_k8s_auth_userpass(kube):
    return {
        "clusters": [
            {
                "name": id,
                "cluster": {
                    "server": kube.get('metadata').get('endpoint'),
                    "insecure-skip-tls-verify": True,
                },
            },
        ],
        "contexts": [
            {
                "name": id,
                "context": {
                    "cluster": id,
                    "user": "admin"
                },
            }
        ],
        "current-context": id,
        "users": [
            {
                "name": "admin",
                "user": {
                    "username": _get_credential(kube, 'username'),
                    "password": _get_credential(kube, 'password'),
                },
            }
        ],
    }


class NamespaceNoDeploymentError(Exception):
    """A Namespace does not have any Deployment objects"""

    pass


class KuberentesError(Exception):
    pass


class KuberentesConnectionError(KuberentesError):
    pass


class BadSecretFormat(Exception):
    pass


class BadEKSToken(Exception):
    pass


class ClusterAttributeError(Exception):
    pass
