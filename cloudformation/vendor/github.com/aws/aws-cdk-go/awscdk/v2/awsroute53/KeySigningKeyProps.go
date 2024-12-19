package awsroute53

import (
	"github.com/aws/aws-cdk-go/awscdk/v2/awskms"
)

// Properties for constructing a Key Signing Key.
//
// Example:
//   var hostedZone hostedZone
//   var kmsKey key
//
//   route53.NewKeySigningKey(this, jsii.String("KeySigningKey"), &KeySigningKeyProps{
//   	HostedZone: HostedZone,
//   	KmsKey: KmsKey,
//   	KeySigningKeyName: jsii.String("ksk"),
//   	Status: route53.KeySigningKeyStatus_ACTIVE,
//   })
//
type KeySigningKeyProps struct {
	// The hosted zone that this key will be used to sign.
	HostedZone IHostedZone `field:"required" json:"hostedZone" yaml:"hostedZone"`
	// The customer-managed KMS key that that will be used to sign the records.
	//
	// The KMS Key must be unique for each KSK within a hosted zone. Additionally, the
	// KMS key must be an asymetric customer-managed key using the ECC_NIST_P256 algorithm.
	// See: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec-cmk-requirements.html
	//
	KmsKey awskms.IKey `field:"required" json:"kmsKey" yaml:"kmsKey"`
	// The name for the key signing key.
	//
	// This name must be unique within a hosted zone.
	// Default: an autogenerated name.
	//
	KeySigningKeyName *string `field:"optional" json:"keySigningKeyName" yaml:"keySigningKeyName"`
	// The status of the key signing key.
	// Default: ACTIVE.
	//
	Status KeySigningKeyStatus `field:"optional" json:"status" yaml:"status"`
}

