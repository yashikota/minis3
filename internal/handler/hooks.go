package handler

import (
	"encoding/xml"
	"io"
	"net/http"

	"github.com/yashikota/minis3/internal/backend"
)

// handlerHooks are a Handler's seams for tests. Each defaults to the real
// operation; a test replaces one on its own Handler (h.hooks.x = ...) to
// inject a failure, so tests never share or restore global state and can
// run in parallel.
type handlerHooks struct {
	verifyPresignedURL                 func(r *http.Request) error
	verifyAuthorizationHeader          func(r *http.Request) error
	ownerForAccessKey                  func(accessKey string) *backend.Owner
	getBucketForLogging                func(h *Handler, bucketName string) (*backend.Bucket, bool)
	requestURIForLogging               func(r *http.Request) string
	getBucketACLForAccessCheck         func(h *Handler, bucketName string) (*backend.AccessControlPolicy, error)
	getObjectACLForAccessCheck         func(h *Handler, bucketName, key, versionID string) (*backend.AccessControlPolicy, error)
	getObjectVersionForLogging         func(h *Handler, bucketName, key, versionID string) (*backend.Object, error)
	putObjectForLogging                func(h *Handler, bucketName, key string, data []byte, opts backend.PutObjectOptions) (*backend.Object, error)
	getBucketACL                       func(h *Handler, bucketName string) (*backend.AccessControlPolicy, error)
	createBucketWithObjectLock         func(h *Handler, bucketName string) error
	createBucket                       func(h *Handler, bucketName string) error
	putBucketACL                       func(h *Handler, bucketName string, acl *backend.AccessControlPolicy) error
	deleteBucket                       func(h *Handler, bucketName string) error
	getBucketUsage                     func(h *Handler, bucketName string) (int, int64, error)
	postObjectPut                      func(h *Handler, bucketName, key string, body []byte, opts backend.PutObjectOptions) (*backend.Object, error)
	postObjectPutACL                   func(h *Handler, bucketName, key, versionID string, acl *backend.AccessControlPolicy) error
	setBucketVersioning                func(h *Handler, bucketName string, status backend.VersioningStatus, mfaDelete backend.MFADeleteStatus) error
	getBucketLocation                  func(h *Handler, bucketName string) (string, error)
	getBucketTagging                   func(h *Handler, bucketName string) (map[string]string, error)
	putBucketTagging                   func(h *Handler, bucketName string, tags map[string]string) error
	deleteBucketTagging                func(h *Handler, bucketName string) error
	getBucketPolicy                    func(h *Handler, bucketName string) (string, error)
	putBucketPolicy                    func(h *Handler, bucketName, policy string, denySelfAccess bool) error
	deleteBucketPolicy                 func(h *Handler, bucketName string) error
	getBucketLifecycleConfiguration    func(h *Handler, bucketName string) (*backend.LifecycleConfiguration, error)
	putBucketLifecycleConfiguration    func(h *Handler, bucketName string, config *backend.LifecycleConfiguration) error
	deleteBucketLifecycleConfiguration func(h *Handler, bucketName string) error
	getBucketEncryption                func(h *Handler, bucketName string) (*backend.ServerSideEncryptionConfiguration, error)
	putBucketEncryption                func(h *Handler, bucketName string, config *backend.ServerSideEncryptionConfiguration) error
	deleteBucketEncryption             func(h *Handler, bucketName string) error
	getBucketCORS                      func(h *Handler, bucketName string) (*backend.CORSConfiguration, error)
	putBucketCORS                      func(h *Handler, bucketName string, config *backend.CORSConfiguration) error
	deleteBucketCORS                   func(h *Handler, bucketName string) error
	getBucketWebsite                   func(h *Handler, bucketName string) (*backend.WebsiteConfiguration, error)
	putBucketWebsite                   func(h *Handler, bucketName string, config *backend.WebsiteConfiguration) error
	deleteBucketWebsite                func(h *Handler, bucketName string) error
	getPublicAccessBlock               func(h *Handler, bucketName string) (*backend.PublicAccessBlockConfiguration, error)
	putPublicAccessBlock               func(h *Handler, bucketName string, config *backend.PublicAccessBlockConfiguration) error
	deletePublicAccessBlock            func(h *Handler, bucketName string) error
	getBucketOwnershipControls         func(h *Handler, bucketName string) (*backend.OwnershipControls, error)
	putBucketOwnershipControls         func(h *Handler, bucketName string, controls *backend.OwnershipControls) error
	deleteBucketOwnershipControls      func(h *Handler, bucketName string) error
	getBucketRequestPayment            func(h *Handler, bucketName string) (*backend.RequestPaymentConfiguration, error)
	putBucketRequestPayment            func(h *Handler, bucketName string, cfg *backend.RequestPaymentConfiguration) error
	getBucketLogging                   func(h *Handler, bucketName string) (*backend.BucketLoggingStatus, error)
	putBucketLogging                   func(h *Handler, bucketName string, status *backend.BucketLoggingStatus) error
	deleteBucketLogging                func(h *Handler, bucketName string) error
	putObject                          func(h *Handler, bucketName, key string, data []byte, opts backend.PutObjectOptions) (*backend.Object, error)
	putObjectACL                       func(h *Handler, bucketName, key, versionID string, acl *backend.AccessControlPolicy) error
	copyObject                         func(h *Handler, srcBucket, srcKey, srcVersionID, dstBucket, dstKey string, opts backend.CopyObjectOptions) (*backend.Object, string, error)
	getObjectACL                       func(h *Handler, bucketName, key, versionID string) (*backend.AccessControlPolicy, error)
	restoreObject                      func(h *Handler, bucketName, key, versionID string, days int) (*backend.RestoreObjectResult, error)
	createMultipartUpload              func(h *Handler, bucketName, key string, opts backend.CreateMultipartUploadOptions) (*backend.MultipartUpload, error)
	uploadPart                         func(h *Handler, bucketName, key, uploadID string, partNumber int, data []byte) (*backend.PartInfo, error)
	completeMultipartUpload            func(h *Handler, bucketName, key, uploadID string, parts []backend.CompletePart) (*backend.Object, error)
	getObjectForMultipartCompletion    func(h *Handler, bucketName, key string) (*backend.Object, error)
	getCompletedUploadObject           func(h *Handler, bucketName, key, uploadID string) (*backend.Object, bool)
	abortMultipartUpload               func(h *Handler, bucketName, key, uploadID string) error
	listMultipartUploads               func(h *Handler, bucketName string, opts backend.ListMultipartUploadsOptions) (*backend.ListMultipartUploadsInternalResult, error)
	listParts                          func(h *Handler, bucketName, key, uploadID string, opts backend.ListPartsOptions) (*backend.ListPartsInternalResult, *backend.MultipartUpload, error)
	copyPart                           func(h *Handler, srcBucket, srcKey, srcVersionID, dstBucket, dstKey, uploadID string, partNumber int, rangeStart, rangeEnd int64) (*backend.PartInfo, error)
	decodeURI                          func(s string) (string, error)
	getObjectLockConfiguration         func(h *Handler, bucketName string) (*backend.ObjectLockConfiguration, error)
	putObjectLockConfiguration         func(h *Handler, bucketName string, config *backend.ObjectLockConfiguration) error
	getObjectRetention                 func(h *Handler, bucketName, key, versionID string) (*backend.ObjectLockRetention, error)
	putObjectRetention                 func(h *Handler, bucketName, key, versionID string, retention *backend.ObjectLockRetention, bypassGovernance bool) error
	getObjectLegalHold                 func(h *Handler, bucketName, key, versionID string) (*backend.ObjectLockLegalHold, error)
	putObjectLegalHold                 func(h *Handler, bucketName, key, versionID string, legalHold *backend.ObjectLockLegalHold) error
	readAll                            func(r io.Reader) ([]byte, error)
	xmlMarshal                         func(v any) ([]byte, error)
}

func defaultHooks() handlerHooks {
	return handlerHooks{
		verifyPresignedURL:        verifyPresignedURL,
		verifyAuthorizationHeader: verifyAuthorizationHeader,
		ownerForAccessKey:         backend.OwnerForAccessKey,
		getBucketForLogging: func(h *Handler, bucketName string) (*backend.Bucket, bool) {
			return h.backend.GetBucket(bucketName)
		},
		requestURIForLogging: func(r *http.Request) string {
			return r.URL.RequestURI()
		},
		getBucketACLForAccessCheck: func(
			h *Handler,
			bucketName string,
		) (*backend.AccessControlPolicy, error) {
			return h.backend.GetBucketACL(bucketName)
		},
		getObjectACLForAccessCheck: func(
			h *Handler,
			bucketName, key, versionID string,
		) (*backend.AccessControlPolicy, error) {
			return h.backend.GetObjectACL(bucketName, key, versionID)
		},
		getObjectVersionForLogging: func(
			h *Handler,
			bucketName, key, versionID string,
		) (*backend.Object, error) {
			return h.backend.GetObjectVersion(bucketName, key, versionID)
		},
		putObjectForLogging: func(
			h *Handler,
			bucketName, key string,
			data []byte,
			opts backend.PutObjectOptions,
		) (*backend.Object, error) {
			return h.backend.PutObject(bucketName, key, data, opts)
		},
		getBucketACL: func(
			h *Handler,
			bucketName string,
		) (*backend.AccessControlPolicy, error) {
			return h.backend.GetBucketACL(bucketName)
		},
		createBucketWithObjectLock: func(h *Handler, bucketName string) error {
			return h.backend.CreateBucketWithObjectLock(bucketName)
		},
		createBucket: func(h *Handler, bucketName string) error {
			return h.backend.CreateBucket(bucketName)
		},
		putBucketACL: func(
			h *Handler,
			bucketName string,
			acl *backend.AccessControlPolicy,
		) error {
			return h.backend.PutBucketACL(bucketName, acl)
		},
		deleteBucket: func(h *Handler, bucketName string) error {
			return h.backend.DeleteBucket(bucketName)
		},
		getBucketUsage: func(h *Handler, bucketName string) (int, int64, error) {
			return h.backend.GetBucketUsage(bucketName)
		},
		postObjectPut: func(
			h *Handler,
			bucketName, key string,
			body []byte,
			opts backend.PutObjectOptions,
		) (*backend.Object, error) {
			return h.backend.PutObject(bucketName, key, body, opts)
		},
		postObjectPutACL: func(
			h *Handler,
			bucketName, key, versionID string,
			acl *backend.AccessControlPolicy,
		) error {
			return h.backend.PutObjectACL(bucketName, key, versionID, acl)
		},
		setBucketVersioning: func(
			h *Handler,
			bucketName string,
			status backend.VersioningStatus,
			mfaDelete backend.MFADeleteStatus,
		) error {
			return h.backend.SetBucketVersioning(bucketName, status, mfaDelete)
		},
		getBucketLocation: func(h *Handler, bucketName string) (string, error) {
			return h.backend.GetBucketLocation(bucketName)
		},
		getBucketTagging: func(h *Handler, bucketName string) (map[string]string, error) {
			return h.backend.GetBucketTagging(bucketName)
		},
		putBucketTagging: func(h *Handler, bucketName string, tags map[string]string) error {
			return h.backend.PutBucketTagging(bucketName, tags)
		},
		deleteBucketTagging: func(h *Handler, bucketName string) error {
			return h.backend.DeleteBucketTagging(bucketName)
		},
		getBucketPolicy: func(h *Handler, bucketName string) (string, error) {
			return h.backend.GetBucketPolicy(bucketName)
		},
		putBucketPolicy: func(h *Handler, bucketName, policy string, denySelfAccess bool) error {
			return h.backend.PutBucketPolicy(bucketName, policy, denySelfAccess)
		},
		deleteBucketPolicy: func(h *Handler, bucketName string) error {
			return h.backend.DeleteBucketPolicy(bucketName)
		},
		getBucketLifecycleConfiguration: func(
			h *Handler,
			bucketName string,
		) (*backend.LifecycleConfiguration, error) {
			return h.backend.GetBucketLifecycleConfiguration(bucketName)
		},
		putBucketLifecycleConfiguration: func(
			h *Handler,
			bucketName string,
			config *backend.LifecycleConfiguration,
		) error {
			return h.backend.PutBucketLifecycleConfiguration(bucketName, config)
		},
		deleteBucketLifecycleConfiguration: func(h *Handler, bucketName string) error {
			return h.backend.DeleteBucketLifecycleConfiguration(bucketName)
		},
		getBucketEncryption: func(
			h *Handler,
			bucketName string,
		) (*backend.ServerSideEncryptionConfiguration, error) {
			return h.backend.GetBucketEncryption(bucketName)
		},
		putBucketEncryption: func(
			h *Handler,
			bucketName string,
			config *backend.ServerSideEncryptionConfiguration,
		) error {
			return h.backend.PutBucketEncryption(bucketName, config)
		},
		deleteBucketEncryption: func(h *Handler, bucketName string) error {
			return h.backend.DeleteBucketEncryption(bucketName)
		},
		getBucketCORS: func(h *Handler, bucketName string) (*backend.CORSConfiguration, error) {
			return h.backend.GetBucketCORS(bucketName)
		},
		putBucketCORS: func(
			h *Handler,
			bucketName string,
			config *backend.CORSConfiguration,
		) error {
			return h.backend.PutBucketCORS(bucketName, config)
		},
		deleteBucketCORS: func(h *Handler, bucketName string) error {
			return h.backend.DeleteBucketCORS(bucketName)
		},
		getBucketWebsite: func(
			h *Handler,
			bucketName string,
		) (*backend.WebsiteConfiguration, error) {
			return h.backend.GetBucketWebsite(bucketName)
		},
		putBucketWebsite: func(
			h *Handler,
			bucketName string,
			config *backend.WebsiteConfiguration,
		) error {
			return h.backend.PutBucketWebsite(bucketName, config)
		},
		deleteBucketWebsite: func(h *Handler, bucketName string) error {
			return h.backend.DeleteBucketWebsite(bucketName)
		},
		getPublicAccessBlock: func(
			h *Handler,
			bucketName string,
		) (*backend.PublicAccessBlockConfiguration, error) {
			return h.backend.GetPublicAccessBlock(bucketName)
		},
		putPublicAccessBlock: func(
			h *Handler,
			bucketName string,
			config *backend.PublicAccessBlockConfiguration,
		) error {
			return h.backend.PutPublicAccessBlock(bucketName, config)
		},
		deletePublicAccessBlock: func(h *Handler, bucketName string) error {
			return h.backend.DeletePublicAccessBlock(bucketName)
		},
		getBucketOwnershipControls: func(
			h *Handler,
			bucketName string,
		) (*backend.OwnershipControls, error) {
			return h.backend.GetBucketOwnershipControls(bucketName)
		},
		putBucketOwnershipControls: func(
			h *Handler,
			bucketName string,
			controls *backend.OwnershipControls,
		) error {
			return h.backend.PutBucketOwnershipControls(bucketName, controls)
		},
		deleteBucketOwnershipControls: func(h *Handler, bucketName string) error {
			return h.backend.DeleteBucketOwnershipControls(bucketName)
		},
		getBucketRequestPayment: func(
			h *Handler,
			bucketName string,
		) (*backend.RequestPaymentConfiguration, error) {
			return h.backend.GetBucketRequestPayment(bucketName)
		},
		putBucketRequestPayment: func(
			h *Handler,
			bucketName string,
			cfg *backend.RequestPaymentConfiguration,
		) error {
			return h.backend.PutBucketRequestPayment(bucketName, cfg)
		},
		getBucketLogging: func(
			h *Handler,
			bucketName string,
		) (*backend.BucketLoggingStatus, error) {
			return h.backend.GetBucketLogging(bucketName)
		},
		putBucketLogging: func(
			h *Handler,
			bucketName string,
			status *backend.BucketLoggingStatus,
		) error {
			return h.backend.PutBucketLogging(bucketName, status)
		},
		deleteBucketLogging: func(h *Handler, bucketName string) error {
			return h.backend.DeleteBucketLogging(bucketName)
		},
		putObject: func(
			h *Handler,
			bucketName, key string,
			data []byte,
			opts backend.PutObjectOptions,
		) (*backend.Object, error) {
			return h.backend.PutObject(bucketName, key, data, opts)
		},
		putObjectACL: func(
			h *Handler,
			bucketName, key, versionID string,
			acl *backend.AccessControlPolicy,
		) error {
			return h.backend.PutObjectACL(bucketName, key, versionID, acl)
		},
		copyObject: func(
			h *Handler,
			srcBucket, srcKey, srcVersionID, dstBucket, dstKey string,
			opts backend.CopyObjectOptions,
		) (*backend.Object, string, error) {
			return h.backend.CopyObject(srcBucket, srcKey, srcVersionID, dstBucket, dstKey, opts)
		},
		getObjectACL: func(
			h *Handler,
			bucketName, key, versionID string,
		) (*backend.AccessControlPolicy, error) {
			return h.backend.GetObjectACL(bucketName, key, versionID)
		},
		restoreObject: func(
			h *Handler,
			bucketName, key, versionID string,
			days int,
		) (*backend.RestoreObjectResult, error) {
			return h.backend.RestoreObject(bucketName, key, versionID, days)
		},
		createMultipartUpload: func(
			h *Handler,
			bucketName, key string,
			opts backend.CreateMultipartUploadOptions,
		) (*backend.MultipartUpload, error) {
			return h.backend.CreateMultipartUpload(bucketName, key, opts)
		},
		uploadPart: func(
			h *Handler,
			bucketName, key, uploadID string,
			partNumber int,
			data []byte,
		) (*backend.PartInfo, error) {
			return h.backend.UploadPart(bucketName, key, uploadID, partNumber, data)
		},
		completeMultipartUpload: func(
			h *Handler,
			bucketName, key, uploadID string,
			parts []backend.CompletePart,
		) (*backend.Object, error) {
			return h.backend.CompleteMultipartUpload(bucketName, key, uploadID, parts)
		},
		getObjectForMultipartCompletion: func(
			h *Handler,
			bucketName, key string,
		) (*backend.Object, error) {
			return h.backend.GetObject(bucketName, key)
		},
		getCompletedUploadObject: func(
			h *Handler,
			bucketName, key, uploadID string,
		) (*backend.Object, bool) {
			return h.backend.GetCompletedUploadObject(bucketName, key, uploadID)
		},
		abortMultipartUpload: func(
			h *Handler,
			bucketName, key, uploadID string,
		) error {
			return h.backend.AbortMultipartUpload(bucketName, key, uploadID)
		},
		listMultipartUploads: func(
			h *Handler,
			bucketName string,
			opts backend.ListMultipartUploadsOptions,
		) (*backend.ListMultipartUploadsInternalResult, error) {
			return h.backend.ListMultipartUploads(bucketName, opts)
		},
		listParts: func(
			h *Handler,
			bucketName, key, uploadID string,
			opts backend.ListPartsOptions,
		) (*backend.ListPartsInternalResult, *backend.MultipartUpload, error) {
			return h.backend.ListParts(bucketName, key, uploadID, opts)
		},
		copyPart: func(
			h *Handler,
			srcBucket, srcKey, srcVersionID, dstBucket, dstKey, uploadID string,
			partNumber int,
			rangeStart, rangeEnd int64,
		) (*backend.PartInfo, error) {
			return h.backend.CopyPart(
				srcBucket,
				srcKey,
				srcVersionID,
				dstBucket,
				dstKey,
				uploadID,
				partNumber,
				rangeStart,
				rangeEnd,
			)
		},
		decodeURI: decodeURI,
		getObjectLockConfiguration: func(
			h *Handler,
			bucketName string,
		) (*backend.ObjectLockConfiguration, error) {
			return h.backend.GetObjectLockConfiguration(bucketName)
		},
		putObjectLockConfiguration: func(
			h *Handler,
			bucketName string,
			config *backend.ObjectLockConfiguration,
		) error {
			return h.backend.PutObjectLockConfiguration(bucketName, config)
		},
		getObjectRetention: func(
			h *Handler,
			bucketName, key, versionID string,
		) (*backend.ObjectLockRetention, error) {
			return h.backend.GetObjectRetention(bucketName, key, versionID)
		},
		putObjectRetention: func(
			h *Handler,
			bucketName, key, versionID string,
			retention *backend.ObjectLockRetention,
			bypassGovernance bool,
		) error {
			return h.backend.PutObjectRetention(
				bucketName,
				key,
				versionID,
				retention,
				bypassGovernance,
			)
		},
		getObjectLegalHold: func(
			h *Handler,
			bucketName, key, versionID string,
		) (*backend.ObjectLockLegalHold, error) {
			return h.backend.GetObjectLegalHold(bucketName, key, versionID)
		},
		putObjectLegalHold: func(
			h *Handler,
			bucketName, key, versionID string,
			legalHold *backend.ObjectLockLegalHold,
		) error {
			return h.backend.PutObjectLegalHold(bucketName, key, versionID, legalHold)
		},
		readAll:    io.ReadAll,
		xmlMarshal: xml.Marshal,
	}
}
