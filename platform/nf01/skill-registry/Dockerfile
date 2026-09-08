FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/security-log-skills-mcp

COPY skill-registry/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY skill-registry/server.py skill-registry/integration_test.py skill-registry/test_registry.py ./

RUN useradd --create-home --uid 10001 mcp \
    && mkdir -p /skills /drafts \
    && chown -R mcp:mcp /opt/security-log-skills-mcp /drafts

USER mcp
EXPOSE 8000
CMD ["python", "server.py"]
