package openid

import (
	"fmt"
	"reflect"
	"testing"
)

var realm = "https://localhost"
var opEndpoint = "https://login.example.com/openid"
var callbackPrefix = "/openid/verify"

// How to test openid without a openid provider ?
// The fake login.example.com/openid is not exist.
func Test_New_0(t *testing.T) {
	o := New(realm)
	if "*openid.OpenID" != fmt.Sprintf("%s", reflect.TypeOf(o)) {
		t.Errorf("New return type error")
	}
}
