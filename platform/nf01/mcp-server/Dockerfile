FROM apache/spark:3.5.6-scala2.12-java17-python3-ubuntu

USER root
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*
COPY mcp-server/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt
COPY mcp-server/server.py mcp-server/integration_test.py mcp-server/demo_analysis.py mcp-server/panos_log_analysis.py mcp-server/generic_security_analysis.py /opt/spark-hdfs-mcp/
COPY mcp-server/evidence_tools.py /opt/spark-hdfs-mcp/
COPY mcp-server/entrypoint.sh /usr/local/bin/spark-hdfs-mcp-entrypoint
RUN chmod 0755 /usr/local/bin/spark-hdfs-mcp-entrypoint \
    && mkdir -p /var/lib/spark-hdfs-mcp /imports \
    && chown spark:spark /var/lib/spark-hdfs-mcp /imports

WORKDIR /opt/spark-hdfs-mcp
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/spark-hdfs-mcp-entrypoint"]
