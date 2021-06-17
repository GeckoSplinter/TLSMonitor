#FROM gcr.io/distroless/static
FROM debian

COPY tlsmonitor /tlsmonitor

EXPOSE 8080
EXPOSE 9090
LABEL version 1.0.0
LABEL name tlsmonitor


ENTRYPOINT ["/tlsmonitor"]
