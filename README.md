# DNS 控制台

网页上统一查看和修改域名解析。支持阿里云、腾讯云 DNSPod、DNSPod Token、Wix 和 GoDaddy。密钥只保存在本机的 `data` 目录。

镜像是 linux/amd64，用于 x86_64 的机器。

镜像主要用 Docker Hub：`plutosdocker/ali-dns-audit:latest`

备用用 GitHub 容器仓库：`ghcr.io/meteor-showers/ali-dns-audit:latest`。Docker Hub 拉不到时，把下面 compose 里的 `image` 换成这个地址。

## Docker

```yaml
services:
  dns-console:
    image: plutosdocker/ali-dns-audit:latest
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

```bash
docker compose pull
docker compose up -d
```

浏览器打开 `http://服务器地址:8080`。第一次打开时创建用户名和密码。`./data` 里是数据库和登录状态。升级时保留这个目录，`docker compose pull` 后再 `up -d` 只换镜像，不会清空已有平台、解析和登录账号。新版本只在原来的数据库里补表。

## 本地运行

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m app
```

浏览器打开 http://127.0.0.1:8080 。需要本机有 `dig` 才能判断公网 NS。

## 使用

1. 登录后在「平台」里添加阿里云、腾讯云 DNSPod、DNSPod Token、Wix 或 GoDaddy。
2. 平台可以单独填代理。留空则用「设置」里的全局代理，两边都空则直连。
3. 首页搜索主域名或子域名，会打开公网正在使用的那一份解析。
4. 可以添加、修改、删除解析。阿里云和腾讯云可以启用或停止单条记录。Wix 和 GoDaddy 没有线路、备注，也不能单独停止一条记录。
5. 不登录也可以搜索和查看记录，不能修改，也看不到平台列表。
6. 搜索子域名后，记录值后面会显示它在阿里云的 CDN、全站加速、直播、点播、OSS 或负载均衡里的使用位置。不登录也能看到。普通 A 记录没有这一项。
7. 设置里可以启用 LDAP。不启用时用本机账号密码。启用后，只有最早创建的管理账号能用本机密码，其他用户用 LDAP 登录。
