# openid

simple OpenID consumer implementation

## description

* associate:

  Consumer --request--> OpenID Server

* checkid_setup:

  Consumer --redirect--> User Agent --request--> OpenID Server

* id_res:

  OpenID Server --redirect--> User Agent --request--> Consuer

## usage example:

```go
realm := "https://localhost"
opEndpoint := "https://openidprovider.com/openid"
callbackPrefix = "/openid/verify"
o = openid.New(realm)
```

redirect to OpenID Server login url:

```go
func loginHandler(w http.ResponseWriter, r *http.Request){
	url, err := o.CheckIDSetup(opEndpoint, callbackPrefix)
	// ...
	http.Redirect(w, r, url, http.StatusFound)
	// ...
}
```

verify OpenID Server redirect back:

```go
func VerifyHander(w http.ResponseWriter, r *http.Request){
	// ...
	user, err := o.IDRes(r)
	// ...
}
```

## IDRes checks

`IDRes` 按顺序校验下面这些，任何一条不过都返回错误：

1. `openid.mode` 必须是 `id_res`（原来不看，`cancel` 也会被当成登录成功）；
2. `openid.ns` 若给出必须是 2.0；
3. `openid.op_endpoint` 非空；设置了 `OpenID.Endpoint` 时还必须等于它；
4. `openid.signed` 非空，签名用 `hmac.Equal` 常量时间比较；
5. `RequireSignedEmail`（默认 true）要求 `sreg.email` 出现在
   `openid.signed` 里——判身份靠这个字段，不签名就等于让客户端说了算；
6. `CheckReturnTo`（默认 true）要求 `openid.return_to` 落在本 realm 的
   回调路径上（回调前缀里可以带 `?state=...`，只比路径）；
7. `openid.response_nonce` 若给出必须被签名，且 5 分钟内不能用第二次。

防重放还要配合调用方：`CheckIDSetup` 的回调前缀里带上一次性 state，
`IDRes` 之后自己比对（见 `github.com/shuaiming/login`）。

```go
o := openid.New("https://status.example.com")
o.Endpoint = "https://login.netease.com/openid"
o.RequireSignedEmail = false // 只在 OP 确实不签 sreg.email 时才关
```
