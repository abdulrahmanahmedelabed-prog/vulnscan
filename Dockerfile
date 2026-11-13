# Kashif (vulnscan) — container image of the command-line scanner and its web UI.
#
#   docker run --rm -v "$PWD:/src" ghcr.io/abdulrahmanahmedelabed-prog/kashif:1 .
#
# The package is standard library only, so the image is the Python runtime, git (for --diff-base, --diff-staged
# and --fix on a work tree) and the wheel. See docs/production.md for the read-only, CI and UI recipes.

# python:3.12-slim (Python 3.12.16 on Debian 13 "trixie"), pinned by the digest of its multi-architecture index
# (linux/amd64 and linux/arm64). No `# syntax=` line: BuildKit's built-in Dockerfile frontend handles RUN --mount, so
# no unpinned frontend image is pulled at build time.
ARG PYTHON_IMAGE=python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# ---------------------------------------------------------------------------------------------------- build the wheel
FROM ${PYTHON_IMAGE} AS build
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY vulnscan ./vulnscan
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /dist .

# ----------------------------------------------------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE}

ARG VERSION=0.0.0-dev
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="Kashif" \
      org.opencontainers.image.description="Kashif (vulnscan): zero-dependency SAST with inter-procedural data-flow analysis for 12 languages, SARIF output and a local web UI." \
      org.opencontainers.image.source="https://github.com/abdulrahmanahmedelabed-prog/vulnscan" \
      org.opencontainers.image.url="https://abdulrahmanahmedelabed-prog.github.io/vulnscan/" \
      org.opencontainers.image.documentation="https://abdulrahmanahmedelabed-prog.github.io/vulnscan/docs.html" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="Kashif (vulnscan) contributors" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.base.name="docker.io/library/python:3.12-slim"

# No .pyc writes at run time (the root filesystem may be read-only), unbuffered output for CI logs, and the UI's
# state (scan history, settings) under /data so that a volume can keep it.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VULNSCAN_HOME=/data \
    HOME=/tmp

# The package versions follow the digest-pinned base image's Debian release.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 # a mounted repository belongs to the host user, not to the image's user: git must still read it
 && git config --system --add safe.directory '*' \
 && groupadd --system --gid 10001 kashif \
 && useradd --system --uid 10001 --gid kashif --home-dir /tmp --no-create-home --shell /usr/sbin/nologin kashif \
 # world-writable with the sticky bit, like /tmp: `docker run --user "$(id -u):$(id -g)"` can still write there
 && mkdir -p /src /data && chmod 1777 /data

# Install the wheel (compiled to .pyc here, once), then drop pip: nothing is installed at run time.
RUN --mount=type=bind,from=build,source=/dist,target=/dist \
    pip install --no-cache-dir --no-index --no-deps /dist/kashif-*.whl \
 && pip uninstall -y pip \
 && kashif --version \
 && vulnscan --version

USER 10001:10001
WORKDIR /src
VOLUME ["/data"]
# No EXPOSE: the UI listens on the loopback interface only, so a published port (-p) would not reach it. Run the UI
# with --network host (docs/production.md, "The web UI in a container").

# `kashif` is the command; `vulnscan` stays installed as an alias (`docker run --entrypoint vulnscan ...`).
ENTRYPOINT ["kashif"]
CMD ["--help"]
