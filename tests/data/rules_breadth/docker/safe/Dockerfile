FROM python:3.12-slim@sha256:0f5f4a1c4b7e2d1c8f9a6b3e2d1c0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a
ENV AWS_ACCESS_KEY=${AWS_ACCESS_KEY}
ARG CLIENT_KEY_FILE=
ENV DB_PASSWORD_FILE=/run/secrets/db
ARG GOOGLE_CREDENTIALS_FILE=/run/secrets/gcp.json
ENV AWS_ACCESS_KEY_ID=AKIA_FROM_BUILD_ARG
RUN apt-get update && apt-get install -y --no-install-recommends curl
# never use --no-check-certificate or curl --insecure here
RUN echo "pseudo sudoers note" > /tmp/readme
EXPOSE 8022 2222 443
RUN curl -fsSL https://downloads.internal/tool.tgz -o /opt/tool.tgz
RUN pip install --index-url https://pypi.internal/simple app
RUN echo "root:locked" > /tmp/account-note
USER 10001
CMD ["python", "-m", "app"]
