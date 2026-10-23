ARG PYTHON_IMAGE=python:3.11-slim
FROM ${PYTHON_IMAGE}

# 本机默认走国内镜像。GitHub Actions 在海外，构建时传入 USE_CN_MIRROR=0。
ARG USE_CN_MIRROR=1
ARG PIP_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple

RUN if [ "$USE_CN_MIRROR" = "1" ]; then \
      if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sed -i 's|http://deb.debian.org|https://mirrors.aliyun.com|g; s|https://deb.debian.org|https://mirrors.aliyun.com|g; s|http://security.debian.org|https://mirrors.aliyun.com|g; s|https://security.debian.org|https://mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources; \
      fi \
      && if [ -f /etc/apt/sources.list ]; then \
        sed -i 's|http://deb.debian.org|https://mirrors.aliyun.com|g; s|https://deb.debian.org|https://mirrors.aliyun.com|g; s|http://security.debian.org|https://mirrors.aliyun.com|g; s|https://security.debian.org|https://mirrors.aliyun.com|g' /etc/apt/sources.list; \
      fi; \
    fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -i "$PIP_INDEX" -r requirements.txt
COPY app ./app
ENV DNS_DATA_DIR=/app/data
RUN mkdir -p /app/data
VOLUME /app/data
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
