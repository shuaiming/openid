package openid

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testRealm = "https://status.example.com"
	testOP    = "https://login.example.com/openid"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

// baseSigned 一条正常回执的签名范围
var baseSigned = []string{
	"op_endpoint", "claimed_id", "identity", "return_to",
	"response_nonce", "assoc_handle", sregEmail,
}

// newTestOpenID 一个已经和 testOP 建好 association 的 consumer
func newTestOpenID(t *testing.T) *OpenID {
	t.Helper()

	o := New(testRealm)
	o.assocs.set(testOP, &Association{
		Endpoint: testOP,
		Handle:   "test-handle",
		Secret:   testSecret,
		Type:     hmacSHA256,
		Expires:  time.Now().Add(time.Hour),
	})
	o.setCallbackPath("/openid/verify")

	return o
}

// baseParams 一条正常回执需要的字段
func baseParams() map[string]string {
	return map[string]string{
		"mode":           "id_res",
		"ns":             Namespace,
		"op_endpoint":    testOP,
		"claimed_id":     ClaimedID,
		"identity":       Identity,
		"return_to":      testRealm + "/openid/verify?state=abc",
		"response_nonce": "2024-01-01T00:00:00Znonce1",
		"assoc_handle":   "test-handle",
		sregEmail:        "a@b.com",
	}
}

// signedRequest 按 signed 列表签好名，拼成一条回执请求
func signedRequest(
	t *testing.T, params map[string]string, signed []string) *http.Request {
	t.Helper()

	q := url.Values{}
	for k, v := range params {
		q.Set("openid."+k, v)
	}

	a := &Association{Type: hmacSHA256, Secret: testSecret}

	sig, err := a.sign(params, signed)
	if err != nil {
		t.Fatal(err)
	}

	q.Set("openid.signed", strings.Join(signed, ","))
	q.Set("openid.sig", sig)

	return httptest.NewRequest(http.MethodGet, "/openid/verify?"+q.Encode(), nil)
}

func TestNew(t *testing.T) {
	o := New(testRealm)
	if o == nil || o.realm != testRealm {
		t.Fatalf("New 返回不对: %+v", o)
	}
}

// TestIDResOK 正常回执能过，并把字段带回来
func TestIDResOK(t *testing.T) {
	user, err := newTestOpenID(t).IDRes(signedRequest(t, baseParams(), baseSigned))
	if err != nil {
		t.Fatalf("正常回执不该报错: %v", err)
	}

	if user[sregEmail] != "a@b.com" {
		t.Errorf("应带回邮箱，实际 %q", user[sregEmail])
	}
}

// TestIDResRejectsNotIdRes mode 不是 id_res 一律拒绝
// 原来不检查 mode：cancel 之类的回执也会被当成登录成功。
func TestIDResRejectsNotIdRes(t *testing.T) {
	params := baseParams()
	params["mode"] = "cancel"

	if _, err := newTestOpenID(t).IDRes(
		signedRequest(t, params, baseSigned)); err == nil {

		t.Error("mode=cancel 应该被拒绝")
	}
}

// TestIDResRequiresSignedEmail 邮箱不在签名范围内时必须拒绝
func TestIDResRequiresSignedEmail(t *testing.T) {
	unsigned := []string{
		"op_endpoint", "claimed_id", "identity", "return_to",
		"response_nonce", "assoc_handle",
	}

	if _, err := newTestOpenID(t).IDRes(
		signedRequest(t, baseParams(), unsigned)); err == nil {

		t.Error("sreg.email 没签名应该被拒绝")
	}

	// 显式关掉之后才放行
	o := newTestOpenID(t)
	o.RequireSignedEmail = false

	if _, err := o.IDRes(signedRequest(t, baseParams(), unsigned)); err != nil {
		t.Errorf("RequireSignedEmail=false 时应放行，实际 %v", err)
	}
}

// TestIDResRejectsTamperedEmail 改了签名没覆盖的字段必须拒绝
func TestIDResRejectsTamperedEmail(t *testing.T) {
	r := signedRequest(t, baseParams(), baseSigned)

	q := r.URL.Query()
	q.Set("openid."+sregEmail, "evil@corp.netease.com")
	r.URL.RawQuery = q.Encode()

	if _, err := newTestOpenID(t).IDRes(r); err == nil {
		t.Error("改写邮箱应该因签名不匹配被拒绝")
	}
}

// TestIDResRejectsReplay 同一条回执（同一个 response_nonce）不能用两次
func TestIDResRejectsReplay(t *testing.T) {
	o := newTestOpenID(t)
	r := signedRequest(t, baseParams(), baseSigned)

	if _, err := o.IDRes(r); err != nil {
		t.Fatalf("第一条回执应该通过: %v", err)
	}

	if _, err := o.IDRes(r); err == nil {
		t.Error("重放同一条回执应该被拒绝")
	}
}

// TestIDResRejectsUnsignedNonce response_nonce 给了却没被签名时拒绝
func TestIDResRejectsUnsignedNonce(t *testing.T) {
	signed := []string{
		"op_endpoint", "claimed_id", "identity", "return_to",
		"assoc_handle", sregEmail,
	}

	if _, err := newTestOpenID(t).IDRes(
		signedRequest(t, baseParams(), signed)); err == nil {

		t.Error("response_nonce 没签名应该被拒绝")
	}
}

// TestIDResRejectsBadReturnTo return_to 不在本 realm 的回调上时拒绝
func TestIDResRejectsBadReturnTo(t *testing.T) {
	cases := map[string]string{
		"别的域名": "https://evil.example.com/openid/verify",
		"别的路径": testRealm + "/other",
		"空的":   "",
	}

	for name, returnTo := range cases {
		t.Run(name, func(t *testing.T) {
			params := baseParams()
			params["return_to"] = returnTo

			if _, err := newTestOpenID(t).IDRes(
				signedRequest(t, params, baseSigned)); err == nil {

				t.Errorf("return_to=%q 应该被拒绝", returnTo)
			}
		})
	}
}

// TestIDResRejectsWrongEndpoint 固定 Endpoint 时，别的 OP 的回执要拒绝
func TestIDResRejectsWrongEndpoint(t *testing.T) {
	o := newTestOpenID(t)
	o.Endpoint = "https://other.example.com/openid"

	if _, err := o.IDRes(signedRequest(t, baseParams(), baseSigned)); err == nil {
		t.Error("op_endpoint 对不上时应该被拒绝")
	}
}

// TestAssociate associate 响应要能解析（含 CRLF 的响应）
func TestAssociate(t *testing.T) {
	secret := []byte("0123456789abcdef")

	op := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("openid.mode"); got != "associate" {
				t.Errorf("openid.mode = %q，应为 associate", got)
			}

			fmt.Fprintf(w, "ns:%s\r\n", Namespace)
			fmt.Fprintf(w, "assoc_type:%s\r\n", hmacSHA256)
			fmt.Fprintf(w, "assoc_handle:%s\r\n", "h1")
			fmt.Fprintf(w, "expires_in:%d\r\n", 3600)
			fmt.Fprintf(w, "mac_key:%s\r\n",
				base64.StdEncoding.EncodeToString(secret))
		}))
	defer op.Close()

	assoc, err := New(testRealm).associate(op.URL)
	if err != nil {
		t.Fatalf("associate 失败: %v", err)
	}

	if assoc.Handle != "h1" {
		t.Errorf("assoc_handle 应为 h1，实际 %q", assoc.Handle)
	}
	if string(assoc.Secret) != string(secret) {
		t.Errorf("mac_key 解出来不对: %q", assoc.Secret)
	}
}

// TestAssociateHTTPError 非 200 时要报错，而不是拿着半截响应往下走
func TestAssociateHTTPError(t *testing.T) {
	op := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
	defer op.Close()

	if _, err := New(testRealm).associate(op.URL); err == nil {
		t.Error("非 200 应该报错")
	}
}
