# Banner Fingerprint

使用 Go 实现的配置驱动 Banner 指纹识别系统。项目包含无状态 HTTP Server 和独立命令行 Client，可批量识别 SSH、HTTP、MySQL、Redis、FTP 等服务；无法识别的记录稳定返回 `protocol: "unknown"`。

## 一键运行

要求 Docker Engine 和 Docker Compose v2。

```bash
docker compose up -d --build server
docker compose run --rm client -input /data/sample-input.json
```

查看健康状态：

```bash
curl http://127.0.0.1:8080/health
```

停止服务：

```bash
docker compose down
```

Client 容器通过 Compose DNS 地址 `http://server:8080` 访问 Server，而不是通过宿主机端口或 `localhost`。Server 对宿主机只绑定 `127.0.0.1:8080`。

## API

### `GET /health`

规则成功加载后返回：

```json
{"rules_loaded":14,"status":"ok"}
```

Compose 健康检查使用 Server 二进制的 `healthcheck` 子命令真实请求该接口，并校验状态和规则数量。

### `POST /fingerprint`

请求体是扫描记录数组：

```json
[
  {
    "ip": "1.2.3.4",
    "port": 22,
    "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
  }
]
```

响应：

```json
[
  {
    "ip": "1.2.3.4",
    "port": 22,
    "protocol": "SSH",
    "product": "OpenSSH",
    "version": "8.9p1",
    "os_hint": "Ubuntu",
    "confidence": 0.95
  }
]
```

无法识别不是接口错误，会返回：

```json
{"ip":"1.2.3.5","port":9999,"protocol":"unknown","product":"","version":"","os_hint":"","confidence":0}
```

默认限制为：请求体 4 MiB、每批 1000 条、单条 Banner 64 KiB。畸形 JSON、非法端口和超限请求分别返回明确的 4xx 响应；单条无法识别不会影响批量中的其他记录。

## Client

本地运行：

```bash
go run ./cmd/client -input testdata/sample-input.json -server http://127.0.0.1:8080
```

参数：

- `-input`：输入 JSON 文件，必填。
- `-server`：Server 基础 URL，默认读取 `SERVER_URL`，否则为 `http://127.0.0.1:8080`。
- `-output`：可选输出文件；省略时写标准输出。
- `-timeout`：整体请求超时，默认 15 秒。
- `-pretty`：是否格式化 JSON，默认开启。

## 指纹规则

规则位于 [`configs/fingerprints.json`](configs/fingerprints.json)，程序启动时加载、校验并预编译，修改识别特征无需重新编译 Go 代码。Compose 将该文件只读挂载到 Server 容器。

一条规则包含：

- `priority`：产品规则应高于通用协议规则。
- `protocol`、`product`：规范化输出。
- `pattern`：Go RE2 正则，可使用 `(?P<version>...)` 命名捕获组。
- `ports`：端口提示，仅调整置信度，不限制匹配。
- `confidence`、`port_bonus`、`port_penalty`：置信度策略。

加载器会拒绝重复 ID、无效正则、不存在的版本捕获组、非法端口和越界置信度。规则按优先级排序，运行期间不可变，可安全供并发请求使用。

## 本地开发与测试

```bash
go test -buildvcs=false ./...
go test -buildvcs=false -race ./...
go vet ./...
go build -buildvcs=false ./cmd/server ./cmd/client
```

启动 Server：

```bash
go run ./cmd/server serve
```

测试数据：

- `testdata/sample-input.json`：全部必需协议和 unknown。
- `testdata/expected-output.json`：样例期望结果。
- `testdata/edge-cases.json`：空 Banner、非标准端口、Unicode 和通用协议特征。

## 部署安全

- Server 和 Client 使用独立的 `scratch` 运行镜像，镜像中不包含源码、Shell、包管理器或 Go 工具链。
- 静态 Go 二进制由固定 Go/Alpine 版本的构建阶段生成。
- 容器以 UID/GID `65532` 运行，根文件系统只读。
- 删除全部 Linux capabilities，启用 `no-new-privileges`。
- 设置 PID、内存和 CPU 限制，并提供 `noexec,nosuid` 临时目录。
- 服务仅加入隔离的内部网络；Client 没有宿主机端口。
- HTTP Server 配置请求头、读取、写入、空闲超时和优雅退出。
- Panic 恢复中间件避免单个异常请求终止进程，访问日志不记录原始 Banner。
