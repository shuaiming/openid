/*
Package openid usage example:
	realm := "https://localhost"
	opEndpoint := "https://openidprovider.com/openid"
	callbackPrefix = "/openid/verify"
	o = openid.New(realm)

redirect to OpenID Server login url:
	func loginHandler(rw http.ResponseWriter, r *http.Request){
		url, err := o.CheckIDSetup(opEndpoint, callbackPrefix)
		...
		http.Redirect(rw, r, url, http.StatusFound)
		...
	}

verify OpenID Server redirect back:
	func VerifyHander(rw http.ResponseWriter, r *http.Request){
		...
		user, err := o.IDRes(r)
		...
	}
*/
package openid

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Namespace openid.ns
const (
	Namespace = "http://specs.openid.net/auth/2.0"
	ClaimedID = "http://specs.openid.net/auth/2.0/identifier"
	Identity  = "http://specs.openid.net/auth/2.0/identifier_select"
	NSSreg    = "http://openid.net/extensions/sreg/1.1"
)

// OpenID implementation
// 1) associate:
//   Consumer --request--> OpenID Server
// 2) checkid_setup:
//   Consumer --redirect--> User Agent --request--> OpenID Server
// 3) id_res:
//   OpenID Server --redirect--> User Agent --request--> Consuer
type OpenID struct {
	assocType string
	realm     string
	assocs    *associations
}

// New openid
// realm is local site, like https://localhost
func New(realm string) *OpenID {

	assocs := &associations{store: map[string]Association{}}
	openid := &OpenID{
		assocType: hmacSHA256,
		realm:     realm,
		assocs:    assocs,
	}

	return openid
}

// CheckIDSetup build redirect url for User Agent
// opEndpoint: OpenID endpoint, like https://openidprovider.com/openid
// callbackPrefix: Consumer urlPrefix which handle the OpenID Server
//   back redirection
func (o *OpenID) CheckIDSetup(
	opEndpoint string, callbackPrefix string) (string, error) {

	assoc := o.associate(opEndpoint)
	if assoc == nil {
		return "", fmt.Errorf("associate with OpenID Server failed")
	}

	values := map[string]string{
		"mode":          "checkid_setup",
		"ns":            Namespace,
		"assoc_handle":  assoc.Handle,
		"return_to":     fmt.Sprintf("%s/%s", o.realm, callbackPrefix),
		"claimed_id":    ClaimedID,
		"identity":      Identity,
		"ns.sreg":       NSSreg,
		"sreg.required": "nickname,email,fullname",
	}

	v := url.Values{}
	encodeHTTP(v, values)

	urlStr := fmt.Sprintf("%s?%s", opEndpoint, v.Encode())
	return urlStr, nil
}

// IDRes handle the OpenID Server back redirection
func (o *OpenID) IDRes(r *http.Request) (map[string]string, error) {

	user := parseHTTP(r.URL.Query())
	endpoint := user["op_endpoint"]

	assocs, ok := o.assocs.get(endpoint)
	if !ok {
		return nil, fmt.Errorf("no Association found for %s", endpoint)
	}

	signed, err := assocs.sign(user, strings.Split(user["signed"], ","))
	if err != nil {
		return nil, err
	} else if signed != user["sig"] {
		return nil, fmt.Errorf("verify singed failed %s", endpoint)
	}

	return user, nil
}

// associate with OpenID Server
// opEndpoint: OpenID endpoint, like https://openidserver.com/openid
func (o *OpenID) associate(opEndpoint string) *Association {
	values := map[string]string{
		"mode":       "associate",
		"assoc_type": o.assocType,
	}

	if assoc, ok := o.assocs.get(opEndpoint); ok {
		return &assoc
	}

	v := url.Values{}
	encodeHTTP(v, values)
	urlStr := fmt.Sprintf("%s?%s", opEndpoint, v.Encode())
	// make a request to OpenID Server asking for associate
	resp, err := http.Get(urlStr)
	if err != nil {
		return nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	openidValues, err := parseKeyValue(body)
	if err != nil {
		return nil
	}

	secret, err := base64.StdEncoding.DecodeString(openidValues["mac_key"])
	if err != nil {
		return nil
	}

	expiresIn, err := strconv.Atoi(openidValues["expires_in"])
	if err != nil {
		return nil
	}
	expiresDu := time.Duration(expiresIn * 1000 * 1000 * 1000)

	assoc := Association{
		Endpoint: opEndpoint,
		Handle:   openidValues["assoc_handle"],
		Secret:   secret,
		Type:     openidValues["assoc_type"],
		Expires:  time.Now().Add(expiresDu),
	}

	// store associate for later use
	o.assocs.set(opEndpoint, assoc)

	return &assoc
}
