FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG GIT_COMMIT=unknown

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-w -s -X main.Version=${VERSION} -X main.BuildTime=$(date -u '+%Y-%m-%d_%H:%M:%S') -X main.GitCommit=${GIT_COMMIT}" \
    -o /certconv ./cmd/certconv

FROM alpine:3.21

RUN apk add --no-cache openssl ca-certificates

COPY --from=builder /certconv /usr/local/bin/certconv

ENTRYPOINT ["certconv"]
