ARG BASE_IMAGE=silk-experiments:r31-mldsa-native
FROM ${BASE_IMAGE}
COPY bin/ /opt/tyche/bin/
COPY benchmark/docker/entrypoint.sh /opt/tyche/entrypoint.sh
RUN chmod 755 /opt/tyche/entrypoint.sh /opt/tyche/bin/*
ENTRYPOINT ["/opt/tyche/entrypoint.sh"]
