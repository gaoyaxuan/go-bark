package bark

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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
	// CBC 模式为 IV (初始化向量)
	// GCM 模式为 Nonce (随机数)
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
			if len(o.Enc.Iv) == 0 {
				return errors.New("CBC mode requires IV")
			}
		case EncModeGCM:
			// GCM Nonce 最好是 12 字节，但我们只在 aesEncrypt 中进行严格校验，这里只检查是否为空。
			if len(o.Enc.Iv) == 0 {
				return errors.New("GCM mode requires Nonce (Iv field)")
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

	// 4. 执行加密
	cipherText, err := aesEncrypt(plainBytes, o.Enc)
	if err != nil {
		return nil, err
	}

	// 5. 构建外部 Payload
	encryptedPayload := make(map[string]interface{})
	encryptedPayload["ciphertext"] = cipherText

	if len(deviceKeysToUse) > 0 {
		finalRoutingKeys := make([]string, 0, len(deviceKeysToUse)+1)
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

// pKCS7Padding 实现了 PKCS7 填充，仅用于 CBC 和 ECB
func pKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// aesEncrypt 使用标准库进行 AES 加密
func aesEncrypt(data []byte, opt *EncOpt) (string, error) {
	key := []byte(opt.Key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	var encrypted []byte
	blockSize := block.BlockSize()
	mode := strings.ToUpper(string(opt.Mode))

	switch mode {
	case "CBC":
		iv := []byte(opt.Iv)
		if len(iv) != blockSize {
			return "", fmt.Errorf("CBC IV length must be %d", blockSize)
		}

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
		nonce := []byte(opt.Iv)
		if len(nonce) != 12 {
			return "", fmt.Errorf("GCM Nonce length must be 12 bytes")
		}

		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		// Seal(dst, nonce, plaintext, additionalData)
		// additionalData 传 nil, plaintext 传未填充的数据
		encrypted = aesGCM.Seal(nil, nonce, data, nil)

	default:
		return "", errors.New("unsupported encryption mode")
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// IntPtr returns a pointer to an int.
func IntPtr(v int) *int {
	return &v
}

func ToPtr[T any](v T) *T {
	return &v
}
