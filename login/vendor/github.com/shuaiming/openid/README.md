# openid
simple OpenID consumer implementation

## description

* associate:

  Consumer --request--> OpenID Server

* checkid_setup:

  Consumer --redirect--> User Agent --request-->
  OpenID Server

* id_res:

  OpenID Server --redirect--> User Agent --request--> Consuer

## usage example:
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
