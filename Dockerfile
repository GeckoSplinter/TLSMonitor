FROM golang:1.16 AS builder
ARG GOOS=linux
ARG GOARCH=amd64
ARG CGO_ENABLED=0

LABEL build_path ./

WORKDIR /tlsmonitor
COPY . .


RUN go mod download
RUN go mod verify
RUN go build -a -tags netgo -ldflags '-w -extldflags "-static"' -o tlsmonitor


# FINAL IMAGE

FROM gcr.io/distroless/base

COPY --from=builder /tlsmonitor/tlsmonitor /tlsmonitor

LABEL version 0.0.7

CMD ["/tlsmonitor"]

