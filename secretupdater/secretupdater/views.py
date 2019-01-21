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

import json
from flask import request
from flask import jsonify

from flask_limiter import Limiter

from secretupdater import app
from secretupdater import basic_auth
from secretupdater.models import process


def get_services_from_body():
    event = request.get_json(force=True)
    if event.get("services") and isinstance(event.get('services'), list):
        return ",".join(event.get("services"))
    return json.dumps(event)


LIMITER = Limiter(app, key_func=get_services_from_body, headers_enabled=True)
for handler in app.logger.handlers:
    LIMITER.logger.addHandler(handler)


@app.route('/internal/health', methods=['GET'])
def internal_healthcheck():
    '''
    Simply return `200 OK` when app is running.
    '''
    return jsonify({"message": "ok"}), 200


@app.route('/v1/update', methods=['POST'])
@LIMITER.limit("1/minute", get_services_from_body)
@basic_auth.required
def receive_webhook():
    '''
    Receive the update notification from the webhook
    The arriving event should be in the format:
    {
        'event_type': event_type,
        'services': services,
        'credentials': credentials
    }
    The 'event_type' can be:
      - 'service_update'
      - 'credential_update'
      - 'blind_credential_update'
    The 'services' will always be a list of services affected by the change.
    The 'credentials' will always be a list of credentials affected.
    '''
    event = request.get_json(force=True)
    if event.get('event_type') and event.get('event_type') in [
            'service_update',
            'credential_update',
            'blind_credential_update'
    ]:
        result = process(event)
        app.logger.debug(result)

        if result['errors']:
            app.logger.warning(result)

        return jsonify({"message": result['errors'] or "OK"}), result['code']

    return jsonify({"message": "invalid request"}), 400
