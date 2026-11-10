FROM node:20 AS build
RUN npm ci
# expect-next: DKR013
FROM python:3.12-slim
# expect-next: DKR006
ENV AWS_ACCESS_KEY=AKIAQWERTYUIOPAS
# expect-next: DKR006
ARG DB_CREDENTIALS=admin:hunter22
# expect-next: DKR007
RUN sudo apt-get update && apt-get install -y curl
# expect-next: DKR008
EXPOSE 8080 22
# expect-next: DKR009
RUN curl -k https://downloads.internal/tool.tgz -o /opt/tool.tgz
# expect-next: DKR009
RUN pip install --trusted-host pypi.internal app
# expect-next: DKR009
RUN apt-get install -y --allow-unauthenticated legacy-pkg
# expect-next: DKR010
RUN echo "root:Sup3rS3cret" | chpasswd
CMD ["python", "-m", "app"]
