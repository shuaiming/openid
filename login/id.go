package login

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/shuaiming/openid"
	"github.com/shuaiming/sessions"
)

const (
	urlKeyRedirect string = "redirect"
	// sesKeyOpenID Session key of OpenID
	sesKeyOpenID string = "github.com/shuaiming/openid/login.User"
	// SesKeyRedirect URL variable key for redirection after verified
	sesKeyRedirect string = "github.com/shuaiming/openid/login.Redirect"
)

// OpenID pod.handler
type OpenID struct {
	prefix   string
	realm    string
	endpoint string
	openid   *openid.OpenID
	redirect string
}

//  New OpenID
func New(prefix, realm, endpoint, keyRedir string) *OpenID {

	if keyRedir == "" {
		keyRedir = urlKeyRedirect
	}

	return &OpenID{
		openid:   openid.New(realm),
		prefix:   prefix,
		realm:    realm,
		endpoint: endpoint,
		redirect: keyRedir,
	}
}

// ServeHTTPimp implement pod.Handler
func (o *OpenID) ServeHTTP(
	rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	if !strings.HasPrefix(r.URL.Path, o.prefix) {
		next(rw, r)
		return
	}

	if r.Method != "GET" && r.Method != "HEAD" {
		next(rw, r)
		return
	}

	s, ok := sessions.GetSession(r)
	if !ok {
		log.Printf("login can not be enabled without session")
		next(rw, r)
		return
	}

	// redirectURL url return back after login/logout
	redirectURL := r.URL.Query().Get(urlKeyRedirect)

	loginURL := fmt.Sprintf("%s/login", o.prefix)
	logoutURL := fmt.Sprintf("%s/logout", o.prefix)
	verifyURL := fmt.Sprintf("%s/verify", o.prefix)

	switch r.URL.Path {
	case loginURL:
		if redirectURL != "" {
			s.Store(sesKeyRedirect, redirectURL)
		}

		// Redirect to OpenID provider
		authURL, err := o.openid.CheckIDSetup(o.endpoint, verifyURL)
		if err != nil {
			log.Println(err)
			return
		}

		http.Redirect(rw, r, authURL, http.StatusFound)

	case logoutURL:
		s.Delete(sesKeyOpenID)
		if redirectURL != "" {
			http.Redirect(rw, r, redirectURL, http.StatusFound)
			s.Delete(sesKeyRedirect)
			return
		}

		rw.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(rw, "logout")

	case verifyURL:
		user, err := o.openid.IDRes(r)
		if err != nil {
			log.Println(err)
			return
		}

		s.Store(sesKeyOpenID, user)

		if redirect, ok := s.Load(sesKeyRedirect); ok {
			http.Redirect(rw, r, redirect.(string), http.StatusFound)
			s.Delete(sesKeyRedirect)
			return
		}

		http.Redirect(rw, r, o.realm, http.StatusFound)

	default:
		next(rw, r)
	}
}

// GetUser return User map
func GetUser(s sessions.Session) (map[string]string, bool) {
	user, ok := s.Load(sesKeyOpenID)

	if !ok {
		return nil, false
	}

	return user.(map[string]string), true
}
