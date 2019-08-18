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

            # Create a hashed value, to see if the data has changed.
            hashedval = hashlib.md5(str(repr(credentials)).encode('utf-8')).hexdigest()

            for kube in k8s_clusters:
                if _get_credential(kube, 'certificate-authority-data'):  # Assuming that if we are given the k8s CA, we're using certs
                    app.logger.debug("Found CA data, assuming we're using x509 for auth")
                    config = {
                        "clusters": [
                            {
                                "name": kube.get('id'),
                                "cluster": {
                                    "server": kube.get('metadata').get('endpoint'),
                                    "certificate-authority-data": _get_credential(kube, 'certificate-authority-data')
                                },
                            },
                        ],
                        "contexts": [
                            {
                                "name": kube.get('id'),
                                "context": {
                                    "cluster": kube.get('id'),
                                    "user": "admin"
                                },
                            }
                        ],
                        "current-context": kube.get('id'),
                        "users": [
                            {
                                "name": "admin",
                                "user": {
                                    "username": _get_credential(kube, 'username'),
                                    "client-certificate-data": _get_credential(kube, 'client-certificate-data'),
                                    "client-key-data": _get_credential(kube, 'client-key-data')
                                }
                            }
                        ]
                    }
                else:
                    app.logger.debug("No CA data available, assuming username/password auth")
                    config = {
                        "clusters": [
                            {
                                "name": kube.get('id'),
                                "cluster": {
                                    "server": kube.get('metadata').get('endpoint'),
                                    "insecure-skip-tls-verify": True
                                },
                            },
                        ],
                        "contexts": [
                            {
                                "name": kube.get('id'),
                                "context": {
                                    "cluster": kube.get('id'),
                                    "user": "admin"
                                },
                            }
                        ],
                        "current-context": kube.get('id'),
                        "users": [
                            {
                                "name": "admin",
                                "user": {
                                    "username": _get_credential(kube, 'username'),
                                    "password": _get_credential(kube, 'password')
                                }
                            }
                        ]
                    }
                app.logger.debug("config: %s", config)
                try:
                    kube_connection = pykube.HTTPClient(pykube.KubeConfig(config))
                    for entry in secret_collection:

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
                            for k in secret_pairs:
                                if k in upper_case_creds:
                                    v = secret_pairs[k]
                                    secret_pairs.pop(k)
                                    secret_pairs[k.upper()] = v

                        if 'secret-case-regex' in entry.get('metadata'):
                            upper_case_regex = entry.get('metadata').get('secret-case-regex').split("\n")
                            for r in upper_case_regex:
                                matching = list(filter(lambda x: re.search(r, x), secret_pairs))
                                for k in matching:
                                    secret_pairs[k.upper()] = secret_pairs[k]
                                    secret_pairs.pop(k)

                        for k, v in secret_pairs.items():
                            if v.lower().startswith("base64:"):
                                secret_pairs[k] = v[7:]
                            else:
                                secret_pairs[k] = base64.b64encode(v.encode('utf-8')).decode('ascii')

                        k8s_secret = {
                            "apiVersion": "v1",
                            "kind": "Secret",
                            "metadata": {
                                "name": secret_name,
                                "namespace": namespace
                            },
                            "type": secret_type,
                            "data": secret_pairs
                        }

                        app.logger.debug(k8s_secret)
                        if pykube.Secret(kube_connection, k8s_secret).exists():
                            pykube.Secret(kube_connection, k8s_secret).delete()  # We delete, rather than update(), as updates seems to keep deleted data
                        pykube.Secret(kube_connection, k8s_secret).create()
                    _trigger_deployment(kube_connection, namespace, checksum=hashedval)  # After updating secrets, we trigger a rolling update in the namespace
                except Exception as e:
                    errors.append(str(e))
                    result_code = 500
                    app.logger.debug(e)
    return {'code': result_code, 'errors': errors}


def _trigger_deployment(kube_connection, namespace, timestamp=datetime.datetime.utcnow(), checksum=None):
    app.logger.debug(str(checksum))
    res = pykube.Deployment.objects(kube_connection).filter(namespace=namespace).all().response
    for deployment in res['items']:
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
        token_cache_file='/tmp/confidant_token'
    )
    app.logger.debug(client.config)
    return client
