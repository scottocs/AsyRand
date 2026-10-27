ARG BASE_IMAGE=silk-experiments:r31-mldsa-native
FROM ${BASE_IMAGE}
ENV TYCHE_ASY_PREDECRYPT=1
ENV TYCHE_ASY_CONSUMER_PRIORITY=1
COPY bin/ /opt/tyche/bin/
COPY benchmark/docker/entrypoint.sh /opt/tyche/entrypoint.sh
RUN chmod 755 /opt/tyche/entrypoint.sh /opt/tyche/bin/*
ENTRYPOINT ["/opt/tyche/entrypoint.sh"]
