ARG BASE_IMAGE=silk-experiments:r31-mldsa-native
FROM ${BASE_IMAGE}
ENV ASYRAND_ASY_PREDECRYPT=1
ENV ASYRAND_ASY_CONSUMER_PRIORITY=1
COPY bin/ /opt/asyrand/bin/
COPY benchmark/docker/entrypoint.sh /opt/asyrand/entrypoint.sh
RUN chmod 755 /opt/asyrand/entrypoint.sh /opt/asyrand/bin/*
ENTRYPOINT ["/opt/asyrand/entrypoint.sh"]
