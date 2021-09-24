FROM golang:1.16 AS builder

WORKDIR /tlsmonitor
COPY . .

RUN go mod download
RUN go mod verify
ARG opts
RUN env ${opts} go build -a -tags netgo -ldflags '-w -extldflags "-static"' -o tlsmonitor


# FINAL IMAGE

FROM gcr.io/distroless/static

COPY --from=builder /tlsmonitor/tlsmonitor /tlsmonitor

EXPOSE 9090
LABEL version 0.1.0
LABEL name tlsmonitor


CMD ["/tlsmonitor"]
