# Analysis and detection image: parsing, features, training, detect, report.
# It does not include libvirt (lab control runs on the KVM host, not in a container).
#
#   docker build -t gaphunter .
#   docker run --rm -v "$PWD:/work" gaphunter detect /work/logs/sysmon.evtx -m /work/model.joblib
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="GapHunter" \
      org.opencontainers.image.source="https://github.com/1337strike/gaphunter" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl \
    && useradd --create-home --uid 10001 gaphunter
COPY configs /opt/gaphunter/configs
USER gaphunter
WORKDIR /work
ENV MPLBACKEND=Agg
ENTRYPOINT ["gaphunter"]
CMD ["--help"]
