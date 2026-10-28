#!/bin/sh
set -eu
mkdir -p /tmp/target
tar -xf /out/target.tar -C /tmp/target
if [ -f /out/dependencies.tar ]; then
    mkdir -p /deps
    tar -xf /out/dependencies.tar -C /deps
fi
exec php "$@"
