FROM golang:1.21-alpine as base

FROM base as builder
# Work directory
WORKDIR /build

RUN go env -w GO111MODULE=on
RUN go env -w GOPROXY=https://goproxy.cn,direct

# Installing dependencies
COPY go.mod go.sum /build/

RUN go mod download

# Copying all the files
COPY . .

# Build our application
RUN go build -o /external-dns-huaweicloud

FROM alpine:latest

COPY --from=builder --chown=root:root external-dns-huaweicloud /bin/

# Drop to unprivileged user to run
USER nobody
CMD ["/bin/external-dns-huaweicloud"]
