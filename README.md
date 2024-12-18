# go-bark

bark 推送 golang sdk，支持加密传输

## Example
```shell
go get github.com/gaoyaxuan/go-bark@latest

```

```Go
package main

import "github.com/gaoyaxuan/go-bark"

func main() {
	err := bark.Push(&bark.Options{
		Msg:   "test",
		Token: "xxxxxxxxxxxxxxxxxxxxxx",
	})
	if err != nil {
		panic(err)
	}

	err = bark.Push(&bark.Options{
		Client: bark.Client{ServerURL: "https://aaa.bbbbb.ccc"},
		Msg:    "test",
		Token:  "xxxxxxxxxxxxxxxxxxxxxx",
		Enc: &bark.EncOpt{
			Mode: bark.CBC,
			Key:  "1234567890abcdef",
			Iv:   "1111111111111111",
		},
	})
	if err != nil {
		panic(err)
	}

	// Client
	c := bark.New("https://aaa.bbbbb.ccc")
	err = c.Push(&bark.Options{
		Msg:   "test",
		Token: "xxxxxxxxxxxxxxxxxxxxxx",
	})
	if err != nil {
		panic(err)
	}
}

```

## Options

```Go
type Client struct {
	// 服务器URL
	Domain string
}   

type Options struct {
    Client `json:"-"`
    
    // token (必填)
    Token string `json:"-"`
    // 推送标题
    Title string `json:"title"`
    // 推送内容 (必填)
    Msg string `json:"body,omitempty"`
    // 消息分组
    Group string `json:"group,omitempty"`
    // 点击推送时，跳转的URL，支持URL Scheme 和 Universal Link
    URL string `json:"url,omitempty"`
    // 推送中断级别
    Level string `json:"level,omitempty"`
    // 指定复制的内容
    Copy *string `json:"copy,omitempty"`
    // 自动复制
    AutoCopy *bool `json:"autoCopy,omitempty"`
    // 推送铃声
    Sound string `json:"sound,omitempty"`
    // 自定义图标，传入URL
    Icon string `json:"icon,omitempty"`
    // 推送角标
    Badge *int `json:"badge,omitempty"`
    // 传 1 保存推送，传其他的不保存推送，不传按APP内设置来决定是否保存。
    IsArchive int `json:"isArchive,omitempty,string"`
    //持续响铃 1 持续响铃30秒
    Call int `json:"call,omitempty,string"`
    //level 为 critical时设置声音大小,取值0-10,不传默认为5
    Volume *int `json:"volume,omitempty,string"`
    // 加密传输
    Enc *EncOpt `json:"-"`
}

type EncOpt struct {
	Mode EncMode
	Key  string
	Iv   string
}
```
