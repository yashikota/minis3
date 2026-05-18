package handler

import (
	"encoding/xml"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzXMLVersioningConfiguration(f *testing.F) {
	f.Add([]byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
	f.Add(
		[]byte(
			`<VersioningConfiguration><Status>Suspended</Status><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>`,
		),
	)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var config backend.VersioningConfiguration
		_ = xml.Unmarshal(data, &config)
	})
}

func FuzzXMLLifecycleConfiguration(f *testing.F) {
	f.Add(
		[]byte(
			`<LifecycleConfiguration><Rule><ID>rule1</ID><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>`,
		),
	)
	f.Add([]byte(`<LifecycleConfiguration></LifecycleConfiguration>`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var config backend.LifecycleConfiguration
		_ = xml.Unmarshal(data, &config)
	})
}

func FuzzXMLCORSConfiguration(f *testing.F) {
	f.Add(
		[]byte(
			`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`,
		),
	)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var config backend.CORSConfiguration
		_ = xml.Unmarshal(data, &config)
	})
}

func FuzzXMLServerSideEncryptionConfiguration(f *testing.F) {
	f.Add(
		[]byte(
			`<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`,
		),
	)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var config backend.ServerSideEncryptionConfiguration
		_ = xml.Unmarshal(data, &config)
	})
}

func FuzzXMLWebsiteConfiguration(f *testing.F) {
	f.Add(
		[]byte(
			`<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>`,
		),
	)
	f.Add(
		[]byte(
			`<WebsiteConfiguration><RedirectAllRequestsTo><HostName>example.com</HostName></RedirectAllRequestsTo></WebsiteConfiguration>`,
		),
	)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var config backend.WebsiteConfiguration
		_ = xml.Unmarshal(data, &config)
	})
}

func FuzzXMLPublicAccessBlockConfiguration(f *testing.F) {
	f.Add(
		[]byte(
			`<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>`,
		),
	)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var config backend.PublicAccessBlockConfiguration
		_ = xml.Unmarshal(data, &config)
	})
}

func FuzzXMLOwnershipControls(f *testing.F) {
	f.Add(
		[]byte(
			`<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>`,
		),
	)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var controls backend.OwnershipControls
		_ = xml.Unmarshal(data, &controls)
	})
}

func FuzzXMLBucketLoggingStatus(f *testing.F) {
	f.Add(
		[]byte(
			`<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>prefix/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>`,
		),
	)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var status backend.BucketLoggingStatus
		_ = xml.Unmarshal(data, &status)
	})
}

func FuzzXMLRequestPaymentConfiguration(f *testing.F) {
	f.Add(
		[]byte(
			`<RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>`,
		),
	)
	f.Add(
		[]byte(
			`<RequestPaymentConfiguration><Payer>BucketOwner</Payer></RequestPaymentConfiguration>`,
		),
	)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var cfg backend.RequestPaymentConfiguration
		_ = xml.Unmarshal(data, &cfg)
	})
}

func FuzzXMLCreateBucketConfiguration(f *testing.F) {
	f.Add(
		[]byte(
			`<CreateBucketConfiguration><LocationConstraint>us-west-2</LocationConstraint></CreateBucketConfiguration>`,
		),
	)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var config backend.CreateBucketConfiguration
		_ = xml.Unmarshal(data, &config)
	})
}

func FuzzXMLRestoreRequest(f *testing.F) {
	f.Add([]byte(`<RestoreRequest><Days>7</Days></RestoreRequest>`))
	f.Add(
		[]byte(
			`<RestoreRequest><Days>1</Days><GlacierJobParameters><Tier>Standard</Tier></GlacierJobParameters></RestoreRequest>`,
		),
	)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var req backend.RestoreRequest
		_ = xml.Unmarshal(data, &req)
	})
}

func FuzzXMLObjectLockRetention(f *testing.F) {
	f.Add(
		[]byte(
			`<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2025-01-01T00:00:00Z</RetainUntilDate></Retention>`,
		),
	)
	f.Add([]byte(`<Retention><Mode>COMPLIANCE</Mode></Retention>`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var retention backend.ObjectLockRetention
		_ = xml.Unmarshal(data, &retention)
	})
}

func FuzzXMLObjectLockLegalHold(f *testing.F) {
	f.Add([]byte(`<LegalHold><Status>ON</Status></LegalHold>`))
	f.Add([]byte(`<LegalHold><Status>OFF</Status></LegalHold>`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var legalHold backend.ObjectLockLegalHold
		_ = xml.Unmarshal(data, &legalHold)
	})
}
