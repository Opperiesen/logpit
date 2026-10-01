# Packages a prebuilt static binary (see .github/workflows/release.yml).
FROM busybox AS prep
RUN mkdir /data && chown 65532:65532 /data

FROM scratch
ARG TARGETARCH
COPY docker-bin/docker-bin-${TARGETARCH}/logpit /logpit
COPY contrib/docker.toml /etc/logpit/logpit.toml
COPY --from=prep /data /data
USER 65532:65532
WORKDIR /data
VOLUME /data
EXPOSE 5514/udp 5514/tcp 8080/tcp
ENTRYPOINT ["/logpit"]
CMD ["--config", "/etc/logpit/logpit.toml"]
