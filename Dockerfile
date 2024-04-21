FROM golang:1.22 as builder
ADD . /src
RUN cd /src && CGO_ENABLED=0 go build ./cmd/whawty-nginx-sso

FROM scratch
COPY --from=builder /src/whawty-nginx-sso /whawty-nginx-sso
ENTRYPOINT [ "/whawty-nginx-sso" ]
CMD [ "--config", "/config/config.yml", "run" ]
