package aliacm

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

const encryptedDataKeyHeader = "Encrypted-Data-Key"

// GetConfigRequest 获取配置参数
type GetConfigRequest struct {
	Tenant string `url:"tenant"`
	DataID string `url:"dataId"`
	Group  string `url:"group"`
}

// GetConfig 获取配置
func (d *Diamond) GetConfig(args *GetConfigRequest) ([]byte, error) {
	if len(args.Group) == 0 {
		args.Group = DefaultGroup
	}
	if len(args.Tenant) == 0 {
		args.Tenant = d.option.tenant
	}
	ip, err := d.QueryIP()
	if err != nil {
		return nil, err
	}
	header := make(http.Header)
	if err := d.withSignature(args.Tenant, args.Group)(header); err != nil {
		return nil, err
	}
	request := d.c.NewRequest().
		WithTimeout(apiTimeout).
		WithPath(acmConfig.String(ip)).
		WithQueryParam(args).
		WithHeader(header).
		Get()
	response, err := d.c.Do(context.TODO(), request)
	if err != nil {
		return nil, err
	}
	if !response.Success() {
		return nil, errors.New(response.String())
	}

	config := response.Body()

	if d.kmsClient != nil {
		dataId := args.DataID[:]
		body := string(response.Body()[:])
		switch {
		case strings.HasPrefix(dataId, "cipher-kms-aes-128-"):
			dataKey, err := d.KMSDecrypt(response.Header().Get(encryptedDataKeyHeader))
			if err != nil {
				return nil, err
			}

			bodyByte, err := base64.StdEncoding.DecodeString(body)
			if err != nil {
				return nil, err
			}
			dataKeyByte, err := base64.StdEncoding.DecodeString(dataKey)
			if err != nil {
				return nil, err
			}

			config, err = AesDecrypt(bodyByte, dataKeyByte)
			if err != nil {
				return nil, err
			}

		case strings.HasPrefix(dataId, "cipher-"):
			configStr, err := d.KMSDecrypt(body)
			if err != nil {
				return nil, err
			}
			config = []byte(configStr)

		}
	}

	return config, nil
}
