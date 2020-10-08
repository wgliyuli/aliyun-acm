package aliacm

import (
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func (d *Diamond) kmsDecrypt(content string) (string, error) {
	if d.kmsClient == nil {
		return "", fmt.Errorf("kms client need to initialize ")
	}
	request := kms.CreateDecryptRequest()
	request.Method = "POST"
	request.Scheme = "https"
	request.AcceptFormat = "json"
	request.CiphertextBlob = content
	response, err := d.kmsClient.Decrypt(request)
	if err != nil {
		return "", err
	}
	return response.Plaintext, nil
}
