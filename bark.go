package bark

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// --- 类型定义和常量 ---

// EncMode 加密模式
type EncMode string

const (
	EncModeCBC EncMode = "CBC"
	EncModeECB EncMode = "ECB"
	EncModeGCM EncMode = "GCM"
)

// EncOpt 加密选项
type EncOpt struct {
	Mode EncMode
	Key  string
	// CBC 模式为 IV (初始化向量)，GCM 模式为 Nonce (随机数)。
	// 留空时会为每次推送自动生成安全随机值，并通过 payload 的 iv 参数
	// 传给服务端以便客户端解密（推荐留空）。
	Iv string
}

type Client struct {
	ServerURL  string
	HTTPClient *http.Client
}

// Options 推送参数结构体 (保持不变)
type Options struct {
	DeviceKey  string   `json:"device_key,omitempty"`
	DeviceKeys []string `json:"device_keys,omitempty"`
	Title      string   `json:"title,omitempty"`
	Body       string   `json:"body,omitempty"`
	Markdown   string   `json:"markdown,omitempty"`
	Subtitle   string   `json:"subtitle,omitempty"`
	Group      string   `json:"group,omitempty"`
	URL        string   `json:"url,omitempty"`
	Icon       string   `json:"icon,omitempty"`
	Sound      string   `json:"sound,omitempty"`
	Badge      *int     `json:"badge,omitempty"`
	Level      string   `json:"level,omitempty"`
	Copy       string   `json:"copy,omitempty"`
	AutoCopy   string   `json:"autoCopy,omitempty"`
	IsArchive  *int     `json:"isArchive,omitempty"`
	Call       string   `json:"call,omitempty"`
	Volume     *int     `json:"volume,omitempty"`
	Action     string   `json:"action,omitempty"`
	ID         string   `json:"id,omitempty"`
	Delete     string   `json:"delete,omitempty"`

	Enc *EncOpt `json:"-"`
}

const DefaultDomain = "api.day.app"
const DefaultURL = "https://" + DefaultDomain

var DefaultClient = New(DefaultURL)

func New(serverURL string) *Client {
	if serverURL == "" {
		serverURL = DefaultURL
	}
	serverURL = strings.TrimSuffix(serverURL, "/")
	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "https://" + serverURL
	}

	return &Client{
		ServerURL: serverURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) Push(o *Options) error {
	if err := o.Validate(); err != nil {
		return err
	}

	payload, err := c.preparePayload(o)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.ServerURL+"/push", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var res struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(respBody, &res); err != nil {
		return fmt.Errorf("status: %d, body: %s", resp.StatusCode, string(respBody))
	}

	if res.Code != 200 {
		return fmt.Errorf("bark error (%d): %s", res.Code, res.Message)
	}

	return nil
}

// --- 校验和 Payload 准备 ---

// Validate 检查核心参数和加密参数的合法性
func (o *Options) Validate() error {
	if len(o.DeviceKey) == 0 && len(o.DeviceKeys) == 0 {
		return errors.New("device_key is required")
	}

	if o.Title == "" && o.Body == "" && o.Markdown == "" {
		return errors.New("notification content is required")
	}

	if o.Enc != nil {
		// 密钥长度校验 (AES-128/192/256 必须是 16, 24, 32 字节)
		keyLen := len(o.Enc.Key)
		if keyLen != 16 && keyLen != 24 && keyLen != 32 {
			return errors.New("encryption key length must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes")
		}

		// 模式和 IV/Nonce 校验
		mode := EncMode(strings.ToUpper(string(o.Enc.Mode)))

		switch mode {
		case EncModeCBC:
			// IV 可留空，留空时自动生成；传入时必须是 16 字节
			if len(o.Enc.Iv) != 0 && len(o.Enc.Iv) != cbcIvSize {
				return fmt.Errorf("CBC IV length must be %d bytes when provided", cbcIvSize)
			}
		case EncModeGCM:
			// Nonce 可留空，留空时自动生成；传入时必须是 12 字节
			if len(o.Enc.Iv) != 0 && len(o.Enc.Iv) != gcmNonceSize {
				return fmt.Errorf("GCM Nonce length must be %d bytes when provided", gcmNonceSize)
			}
		case EncModeECB:
			// ECB 不需要 IV/Nonce
		default:
			return fmt.Errorf("unsupported encryption mode: %s (supported: CBC, ECB, GCM)", o.Enc.Mode)
		}
	}

	return nil
}

// preparePayload 处理普通 JSON 或加密 JSON
func (c *Client) preparePayload(o *Options) ([]byte, error) {
	if o.Enc == nil {
		// 不加密推送,并不会把device_keys带到每个客户端
		return json.Marshal(o)
	}

	// 1. 存储用于外部路由的 Keys
	deviceKeyToUse := o.DeviceKey
	deviceKeysToUse := o.DeviceKeys

	// 2. 创建 Options 副本
	// 把device_keys 带到每个客户端可能会泄露,所以清除Keys 和 Enc 字段
	encOpts := *o
	encOpts.DeviceKey = ""
	encOpts.DeviceKeys = nil
	encOpts.Enc = nil

	// 3. 序列化仅含内容的 Options 副本 (plain text)
	plainBytes, err := json.Marshal(encOpts)
	if err != nil {
		return nil, err
	}

	// 4. 执行加密（Iv 为空时自动生成，返回实际使用的 iv）
	cipherText, ivUsed, err := aesEncrypt(plainBytes, o.Enc)
	if err != nil {
		return nil, err
	}

	// 5. 构建外部 Payload
	encryptedPayload := make(map[string]interface{})
	encryptedPayload["ciphertext"] = cipherText
	if ivUsed != "" {
		encryptedPayload["iv"] = ivUsed
	}

	if len(deviceKeysToUse) > 0 {
		finalRoutingKeys := make([]string, len(deviceKeysToUse), len(deviceKeysToUse)+1)
		copy(finalRoutingKeys, deviceKeysToUse)
		// device_key 和 device_keys 可能同时存在
		if deviceKeyToUse != "" && !slices.Contains(finalRoutingKeys, deviceKeyToUse) {
			finalRoutingKeys = append(finalRoutingKeys, deviceKeyToUse)
		}

		if len(finalRoutingKeys) > 1 {
			encryptedPayload["device_keys"] = finalRoutingKeys
		} else if len(finalRoutingKeys) == 1 {
			encryptedPayload["device_key"] = finalRoutingKeys[0]
		} else {
			return nil, errors.New("missing device key for routing")
		}
	} else {
		encryptedPayload["device_key"] = deviceKeyToUse
	}

	return json.Marshal(encryptedPayload)
}

// --- AES 加密实现 ---

const (
	cbcIvSize    = aes.BlockSize // 16
	gcmNonceSize = 12
)

// pKCS7Padding 实现了 PKCS7 填充，仅用于 CBC 和 ECB
func pKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// randomIv 生成 n 字符的随机字母数字 IV/Nonce。
// Bark 客户端把 iv 参数按字符串的 UTF-8 字节使用，所以必须是可打印字符
// 才能通过 JSON/URL 原样传输。随机源为 crypto/rand，并使用拒绝采样
// 消除模偏差，保证每个字符在 62 个候选中均匀分布：
// CBC 需要 IV 不可预测（CSPRNG 满足）；GCM 需要 Nonce 不重复
// （12 字符 ≈ 71 bits 熵，碰撞概率可忽略）。
func randomIv(n int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// 248 是 <=255 中最大的 62 的倍数，超出则拒绝重采样，避免取模偏差
	const maxUnbiased = 248
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b >= maxUnbiased {
				continue
			}
			out = append(out, charset[int(b)%len(charset)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

// aesEncrypt 使用标准库进行 AES 加密。
// 返回密文和实际使用的 IV/Nonce（ECB 模式返回空字符串）。
// opt.Iv 为空时按对应模式的安全要求随机生成。
func aesEncrypt(data []byte, opt *EncOpt) (string, string, error) {
	key := []byte(opt.Key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	var encrypted []byte
	var ivUsed string
	blockSize := block.BlockSize()
	mode := strings.ToUpper(string(opt.Mode))

	switch mode {
	case "CBC":
		ivStr := opt.Iv
		if ivStr == "" {
			if ivStr, err = randomIv(cbcIvSize); err != nil {
				return "", "", err
			}
		}
		iv := []byte(ivStr)
		if len(iv) != blockSize {
			return "", "", fmt.Errorf("CBC IV length must be %d", blockSize)
		}
		ivUsed = ivStr

		paddedData := pKCS7Padding(data, blockSize)
		blockMode := cipher.NewCBCEncrypter(block, iv)
		encrypted = make([]byte, len(paddedData))
		blockMode.CryptBlocks(encrypted, paddedData)

	case "ECB":
		paddedData := pKCS7Padding(data, blockSize)
		encrypted = make([]byte, len(paddedData))
		for i := 0; i < len(paddedData); i += blockSize {
			block.Encrypt(encrypted[i:i+blockSize], paddedData[i:i+blockSize])
		}

	case "GCM":
		// GCM 模式 (AEAD) - 不使用 PKCS7 填充
		nonceStr := opt.Iv
		if nonceStr == "" {
			if nonceStr, err = randomIv(gcmNonceSize); err != nil {
				return "", "", err
			}
		}
		nonce := []byte(nonceStr)
		if len(nonce) != gcmNonceSize {
			return "", "", fmt.Errorf("GCM Nonce length must be %d bytes", gcmNonceSize)
		}
		ivUsed = nonceStr

		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return "", "", err
		}
		// Seal(dst, nonce, plaintext, additionalData)
		// additionalData 传 nil, plaintext 传未填充的数据
		encrypted = aesGCM.Seal(nil, nonce, data, nil)

	default:
		return "", "", errors.New("unsupported encryption mode")
	}

	return base64.StdEncoding.EncodeToString(encrypted), ivUsed, nil
}

// IntPtr returns a pointer to an int.
func IntPtr(v int) *int {
	return &v
}

func ToPtr[T any](v T) *T {
	return &v
}
