# The live demo site (demo/server.py), one image.
#
#   docker build -t sm-divergence-demo . && docker run -p 8080:8080 -v quilt-data:/data sm-divergence-demo
#
# /data holds the site's signing key (so records stay verifiable across deploys) and the latest run
# of each story. Mount a volume there.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_LINK_MODE=copy QUILT_DATA=/data PORT=8080

WORKDIR /app
RUN pip install --no-cache-dir uv
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY sm_divergence ./sm_divergence
RUN uv sync --frozen --no-dev --extra site
COPY demo ./demo

ENV PATH="/app/.venv/bin:$PATH"
RUN mkdir -p /data && useradd -m quilt && chown -R quilt /data /app
USER quilt
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:%s/health'%os.environ['PORT'])"
CMD ["python", "-m", "demo.server"]
