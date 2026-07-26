# Bark Go SDK

一个用 Go 语言编写的 [Bark](https://github.com/Finb/Bark) 推送通知客户端库，支持多种加密模式。

## ✨ 功能特性

- ✅ 支持所有 Bark 推送参数
- ✅ 支持单设备和多设备推送
- ✅ 支持三种加密模式：CBC、ECB、GCM
- ✅ 自定义服务器地址
- ✅ 简单易用的 API

## 📦 安装

```bash
  go get github.com/gaoyaxuan/go-bark@latest
```

## 📖 使用方法

### 1. 基础推送（使用默认客户端）

最简单的推送方法，使用默认的 `https://api.day.app` 服务器。

```go
package main

import (
	"log"

	"github.com/gaoyaxuan/go-bark"
)

func main() {
	// 1. 定义一个 Options 结构体
	options := &bark.Options{
		DeviceKey: "YOUR_DEVICE_KEY", // 必填：你的 Bark Key
		Title:     "Go Push Test",
		Body:      "这是一个来自 Go 程序的推送通知。",
		Sound:     "alarm",
		Level:     "timeSensitive",
		Badge:  bark.IntPtr(500),
	}
	// 2. 使用默认客户端推送（自动发送到 DefaultURL/push）
	if err := bark.DefaultClient.Push(options); err != nil {
		log.Fatalf("推送失败: %v", err)
	}

	log.Println("推送成功!")
}

```

### 2. 自定义服务器和客户端

如果您使用自建的 Bark 服务器，或者需要设置不同的超时时间。

```go
package main

import (
	"log"
	"time"

	"github.com/gaoyaxuan/go-bark"
)

func main() {
	// 1. 创建一个自定义客户端
	// 如果 URL 缺少协议，New 函数将自动补全为 https://
	// 如果使用http,请填写完整地址 http://your.private.bark.server.com
	customURL := "your.private.bark.server.com:8080"
	customClient := bark.New(customURL)

	// 覆盖默认的 10s 超时
	customClient.HTTPClient.Timeout = 15 * time.Second

	options := &bark.Options{
		DeviceKey: "YOUR_DEVICE_KEY",
		Title:     "Custom Server",
		Body:      "来自自定义服务器的推送。",
	}

	// 2. 使用自定义客户端推送
	if err := customClient.Push(options); err != nil {
		log.Fatalf("自定义服务器推送失败: %v", err)
	}

	log.Println("自定义服务器推送成功!")
}

```

### 3. 批量推送（DeviceKeys）

您可以同时向多个设备 Key 推送相同的内容。

```go
package main

import (
	"log"

	"github.com/gaoyaxuan/go-bark"
)

func main() {
	options := &bark.Options{
		DeviceKeys: []string{
			"KEY_FOR_DEVICE_A",
			"KEY_FOR_DEVICE_B",
			"KEY_FOR_DEVICE_C",
		},
		Title: "批量通知",
		Body:  "这个消息将发送给三个设备。",
		Group: "BatchGroup",
	}

	if err := bark.DefaultClient.Push(options); err != nil {
		log.Fatalf("批量推送失败: %v", err)
	}

	log.Println("批量推送成功!")
}

```

### 4. AES 加密推送（GCM 模式 - 推荐）

GCM (Galois/Counter Mode) 是推荐的 AEAD 模式。

**要求：**
- **Key 长度**：16 (AES-128), 24 (AES-192), 或 32 (AES-256) 字节
- **Iv 字段**：可留空（推荐）。留空时每次推送自动生成 12 字节的安全随机 Nonce，并通过 payload 的 `iv` 参数传给服务端供客户端解密；传入时必须是 **12 字节**

```go
package main

import (
	"log"

	"github.com/gaoyaxuan/go-bark"
)

const (
	AESKey128 = "16byteskey123456"
)

func main() {

	customURL := "your.private.bark.server.com:8080"
	customClient := bark.New(customURL)
	gcmOptions := &bark.Options{
		DeviceKey: "YOUR_ENCRYPTED_DEVICE_KEY",
		Title:     "GCM 加密推送",
		Body:      "这是使用 GCM 模式加密的内容。",
		Enc: &bark.EncOpt{
			Mode: bark.EncModeGCM, // 使用 GCM 模式
			Key:  AESKey128,
			// Iv 留空：自动生成随机 Nonce（推荐）
			// Iv: "12bytesnonce", // 也可自行指定 12 字节 Nonce
		},
	}

	if err := customClient.Push(gcmOptions); err != nil {
		log.Fatalf("GCM 加密推送失败: %v", err)
	}

	log.Println("GCM 加密推送成功!")
}
```

### 5. AES 加密推送（CBC 或 ECB 模式）

CBC/ECB 是块加密模式。

**要求：**
- **Key 长度**：16, 24, 或 32 字节
- **CBC 模式**：Iv 字段可留空（推荐），留空时自动生成 16 字节安全随机 IV 并通过 payload 的 `iv` 参数传给服务端；传入时必须是 **16 字节**
- **ECB 模式**：不需要 IV，Iv 字段可为空

```go
package main

import (
	"log"

	"github.com/gaoyaxuan/go-bark"
)

const (
	AESKey256 = "32byteskey32byteskey32byteskey32"
)

func main() {

	customURL := "your.private.bark.server.com:8080"
	customClient := bark.New(customURL)
	cbcOptions := &bark.Options{
		DeviceKey: "YOUR_ENCRYPTED_DEVICE_KEY",
		Title:     "CBC 加密推送",
		Body:      "这是使用 CBC 模式加密的内容。",
		Enc: &bark.EncOpt{
			Mode: bark.EncModeCBC, // 使用 CBC 模式
			Key:  AESKey256,
			// Iv 留空：每次推送自动生成不可预测的随机 IV（推荐）
			// Iv: "16bytesiv1234567", // 也可自行指定 16 字节 IV（不推荐固定值）
		},
	}

	if err := customClient.Push(cbcOptions); err != nil {
		log.Fatalf("CBC 加密推送失败: %v", err)
	}

	log.Println("CBC 加密推送成功!")
}

```

**ECB 模式示例：**

```go
package main

import (
	"log"

	"github.com/gaoyaxuan/go-bark"
)

const (
	AESKey256 = "32byteskey32byteskey32byteskey32"
)

func main() {

	customURL := "your.private.bark.server.com:8080"
	customClient := bark.New(customURL)
	ecbOptions := &bark.Options{
		DeviceKey: "YOUR_ENCRYPTED_DEVICE_KEY",
		Title:     "GCM 加密推送",
		Body:      "这是使用 GCM 模式加密的内容。",
		Enc: &bark.EncOpt{
			Mode: bark.EncModeECB, // 使用 CBC 模式
			Key:  AESKey256,
			// ECB 模式不需要 IV
		},
	}

	if err := customClient.Push(ecbOptions); err != nil {
		log.Fatalf("GCM 加密推送失败: %v", err)
	}

	log.Println("GCM 加密推送成功!")
}

```

## 📋 完整参数说明
[Bark Request Parameters ](https://bark.day.app/#/tutorial?id=%e8%af%b7%e6%b1%82%e5%8f%82%e6%95%b0)

## 🔐 加密模式对照表

| 模式 | Key 长度 | IV/Nonce 长度 | 安全性 | 推荐度 |
|------|---------|--------------|--------|--------|
| **GCM** | 16/24/32 字节 | 12 字节（Nonce） | ⭐⭐⭐⭐⭐ | ✅ 强烈推荐 |
| **CBC** | 16/24/32 字节 | 16 字节（IV） | ⭐⭐⭐⭐ | ✅ 推荐 |
| **ECB** | 16/24/32 字节 | 不需要 | ⭐⭐ | ⚠️ 不推荐生产环境 |

## ⚠️ 注意事项

1. **DeviceKey 必填**：`DeviceKey` 或 `DeviceKeys` 至少需要提供一个
2. **内容必填**：`Title`、`Body` 或 `Markdown` 至少需要提供一个
3. **加密密钥安全**：请妥善保管您的加密密钥，不要硬编码在代码中
4. **GCM 模式优先**：生产环境推荐使用 GCM 模式，提供更好的安全性
5. **ECB 模式限制**：ECB 模式不够安全，仅适用于测试环境

## 📝 License

MIT