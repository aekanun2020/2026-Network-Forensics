#!/usr/bin/env bash
set -euo pipefail

state_dir="${JOB_STATE_DIR:-/var/lib/spark-hdfs-mcp}"
mkdir -p "$state_dir"
chown spark:spark "$state_dir"

exec runuser -u spark -- python3 /opt/spark-hdfs-mcp/server.py
