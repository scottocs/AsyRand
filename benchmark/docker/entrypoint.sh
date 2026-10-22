#!/bin/sh
set -eu
printf '%s\n' "$NODE_NEIGHBORS" | while IFS='|' read -r address mac; do
    [ -n "$address" ] || continue
    ip neigh replace "$address" lladdr "$mac" dev eth0 nud permanent
done
# Exact uniform network profile from Silk's Docker entrypoint. The default
# jitter distribution is uniform; no external uniform.dist file is needed.
tc qdisc replace dev eth0 root netem delay 20ms 10ms loss 0% reorder 0% duplicate 0% rate 1000mbit seed "$NETEM_SEED"
tc -details qdisc show dev eth0
touch /results/ready
while [ ! -f /control/start ]; do sleep 0.1; done
exec "$@"
