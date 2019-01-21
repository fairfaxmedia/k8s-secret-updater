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

from os import getenv


def bool_env(var_name, default=False):
    """
    Get an environment variable coerced to a boolean value.
    """
    test_val = getenv(var_name, default)
    # Explicitly check for 'False', 'false', and '0' since all non-empty
    # string are normally coerced to True.
    if test_val in ('False', 'false', '0'):
        return False
    return bool(test_val)


def float_env(var_name, default=0.0):
    """
    Get an environment variable coerced to a float value.
    """
    return float(getenv(var_name, default))


def int_env(var_name, default=0):
    """
    Get an environment variable coerced to an integer value.
    """
    return int(getenv(var_name, default))


def str_env(var_name, default=''):
    """
    Get an environment variable as a string.
    """
    return getenv(var_name, default)


class Config():
    # Basic setup

    # Whether or not the app is run in debug mode. Never run in debug
    # mode outside of development!
    DEBUG = bool_env('DEBUG', False)
    # The host the WSGI app should use.
    HOST = str_env('HOST', '0.0.0.0')
    # The port the WSGI app should use.
    PORT = int_env('PORT', 8080)

    # User auth
    BASIC_AUTH_USERNAME = str_env('USERNAME')
    BASIC_AUTH_PASSWORD = str_env('PASSWORD')
    BASIC_AUTH_REALM = str_env('AUTH_REALM', 'Kubernetes Secret Updater')

    # Confidant server details
    AUTH_METHOD = str_env('AUTH_METHOD', 'saml')  # How to access confidant from app: 'saml' or 'header'

    CONFIDANT_SERVER_URL = str_env('CONFIDANT_SERVER_URL', 'http://localhost')  # ARN
    CONFIDANT_SERVER_AUTH_KEY = str_env(
        'CONFIDANT_SERVER_AUTH_KEY', 'auth-key')
    CONFIDANT_SERVER_AWS_REGION = str_env(
        'CONFIDANT_SERVER_AWS_REGION', 'ap-southeast-2')
