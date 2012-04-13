package services

import (
	"github.com/sunfmin/goauth"
	"testing"
)

func TestGoogle(t *testing.T) {
	goauth.Verbose = true
	g := goauth.NewClient("anonymous", "anonymous", GOOGLE)
	g.Scope = "https://www.google.com/base/feeds/"
	g.RequestMethod = "GET"
	_, tc, err := g.GetAuthorizeURL("http://googlecodesamples.com/oauth_playground/index.php")
	if err != nil || tc.OAuthToken == "" {
		t.Errorf("OAuthToken shouldn't be empty %+v", tc)
	}
}
