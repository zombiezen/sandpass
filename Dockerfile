# Copyright 2019 The Sandpass Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM debian:stretch-slim AS bridge
ENV SANDSTORM_VERSION=248
RUN apt-get update && apt-get install -y \
    binutils \
    curl \
    ca-certificates \
    tar \
    xz-utils \
  && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://dl.sandstorm.io/sandstorm-248.tar.xz \
    | xzcat \
    | tar -Oxf - sandstorm-248/bin/sandstorm-http-bridge > sandstorm-http-bridge \
  && chmod +x sandstorm-http-bridge \
  && strip sandstorm-http-bridge

FROM golang:1.12 AS build
ENV GO111MODULE=on
ENV GOPROXY=https://proxy.golang.org/
# Warm up module cache.
# Only copy in go.mod and go.sum to increase Docker cache hit rate.
COPY go.mod go.sum /sandpass/
WORKDIR /sandpass
RUN go mod download
# Now build the whole tree.
COPY . /sandpass
RUN go build
RUN chmod +x sandpass

FROM gcr.io/distroless/base
COPY --from=bridge /sandstorm-http-bridge /
COPY style.css /opt/app/
COPY js /opt/app/js
COPY templates /opt/app/templates
COPY third_party/roboto/*.woff /opt/app/third_party/roboto/
COPY third_party/clipboard.js/dist/clipboard.min.js /opt/app/third_party/clipboard.js/dist/clipboard.min.js
COPY third_party/scowl/words /usr/share/dict/words
COPY --from=build /sandpass/sandpass /opt/app/sandpass
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/opt/app/sandpass", \
  "-listen=[::]:8080", \
  "-db=/data/keepass.kdb", \
  "-session_key=/data/session_key.json", \
  "-static_dir=/opt/app", \
  "-templates_dir=/opt/app/templates", \
  "-permissions=false"]
