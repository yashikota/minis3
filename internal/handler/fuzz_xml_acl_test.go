package handler

import (
	"encoding/xml"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzXMLAccessControlPolicy(f *testing.F) {
	f.Add(
		[]byte(
			`<AccessControlPolicy><Owner><ID>owner-id</ID><DisplayName>owner</DisplayName></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>user-id</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`,
		),
	)
	f.Add(
		[]byte(
			`<AccessControlPolicy><Owner><ID>id</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>`,
		),
	)
	f.Add([]byte(`<AccessControlPolicy></AccessControlPolicy>`))
	f.Add([]byte{})
	f.Add([]byte(`not xml`))
	f.Add(
		[]byte(
			`<AccessControlPolicy><Owner><ID></ID></Owner><AccessControlList></AccessControlList></AccessControlPolicy>`,
		),
	)

	f.Fuzz(func(t *testing.T, data []byte) {
		var acl backend.AccessControlPolicy
		_ = xml.Unmarshal(data, &acl)
	})
}
