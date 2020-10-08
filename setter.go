package aliacm

import "github.com/aliyun/alibaba-cloud-sdk-go/services/kms"

// Setter configures the diamond.
type Setter func(d *Diamond) error

func WithAcm(addr, tenant, accessKey, secretKey string) Setter {
	return func(d *Diamond) error {
		d.option.AcmOption.addr = addr
		d.option.AcmOption.tenant = tenant
		d.option.AcmOption.accessKey = accessKey
		d.option.AcmOption.secretKey = secretKey
		return nil
	}
}

func WithKms(regionId, accessKey, secretKey string) Setter {
	return func(d *Diamond) error {
		d.option.KmsOption.regionId = regionId
		d.option.KmsOption.accessKey = accessKey
		d.option.KmsOption.secretKey = secretKey

		kmsClient, err := kms.NewClientWithAccessKey(regionId, accessKey, secretKey)
		if err != nil {
			return err
		}
		d.kmsClient = kmsClient

		return nil
	}
}
