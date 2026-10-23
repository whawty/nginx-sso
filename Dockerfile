# The binary is cross-compiled on the platform of the build host, which is much
# faster than compiling it in an emulated container of the target platform.
FROM --platform=$BUILDPLATFORM golang:1.27 AS builder
ARG TARGETOS TARGETARCH TARGETVARIANT
ADD . /src
RUN cd /src && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} go build ./cmd/whawty-nginx-sso

FROM scratch
COPY --from=builder /src/whawty-nginx-sso /whawty-nginx-sso
ENTRYPOINT [ "/whawty-nginx-sso" ]
CMD [ "--config", "/config/config.yml", "run" ]
