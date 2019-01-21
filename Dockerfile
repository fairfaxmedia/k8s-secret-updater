FROM python:3-alpine3.8 AS base
FROM base AS builder

WORKDIR /srv
RUN apk add --no-cache --update alpine-sdk~=1.0 libffi~=3.2 libffi-dev~=3.2 openssl-dev~=1.0
COPY ./secretupdater/requirements.txt .
RUN pip install --install-option="--prefix=/srv" --requirement ./requirements.txt

FROM base AS app

COPY --from=builder /srv /usr/local
WORKDIR /srv
COPY secretupdater/ secretupdater
WORKDIR /srv/secretupdater

CMD ["./runserver.py"]

FROM app AS test

COPY ./secretupdater/requirements-testing.txt .
RUN pip install --quiet --requirement ./requirements-testing.txt
RUN pip freeze
RUN find ./secretupdater -name '*.py' -exec python -m py_compile {} \;
RUN python -m compileall -q .
RUN pylama .

FROM app
