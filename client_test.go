package goauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
)

var sinaconfig = &Configuration{
	RequestTokenURL:        "http://api.t.sina.com.cn/oauth/request_token",
	AccessTokenURL:         "http://api.t.sina.com.cn/oauth/access_token",
	AuthorizeURL:           "http://api.t.sina.com.cn/oauth/authorize",
	UseAuthorizationHeader: true,
	UseBodyHash:            true,
}

var qqconfig = &Configuration{
	RequestTokenURL:        "http://open.t.qq.com/cgi-bin/request_token",
	AccessTokenURL:         "http://open.t.qq.com/cgi-bin/access_token",
	AuthorizeURL:           "http://open.t.qq.com/cgi-bin/authorize",
	UseAuthorizationHeader: false,
	UseBodyHash:            false,
}

func getClientKeyMap() (cc map[string]*ClientCredential) {
	f, err := os.Open(os.Getenv("HOME") + "/.goauth.json")
	if err != nil {
		panic(err)
	}
	bs, _ := ioutil.ReadAll(f)

	json.Unmarshal(bs, &cc)

	return cc
}

func TestErrorWithWrongClientKey(t *testing.T) {
	c := NewClient("wrongkey", "wrongsecret", sinaconfig)
	tc, err := c.GetTemporaryCredential("http://fanlixuxian.com/weibo/login")
	if err == nil {
		t.Errorf("expecting error, but got %+v", tc)
	}
}

func TestGetTemporaryCredentialForWeibo(t *testing.T) {
	cc := getClientKeyMap()["weibo"]

	c := NewClient(cc.Key, cc.Secret, sinaconfig)
	tc, err := c.GetTemporaryCredential("http://fanliwuxian.com/weibo/login")
	if err != nil {
		t.Errorf("error returned %+v", err)
	}
	if tc.OAuthSecret == "" {
		t.Errorf("should return proper temprary credentials %+v", tc)
	}
}

func TestGetTemporaryCredentialForQQ(t *testing.T) {
	cc := getClientKeyMap()["qq"]

	c := NewClient(cc.Key, cc.Secret, qqconfig)
	tc, err := c.GetTemporaryCredential("http://fanliwuxian.com/weibo/login")
	if err != nil {
		t.Errorf("error returned %+v", err)
	}
	if tc.OAuthSecret == "" {
		t.Errorf("should return proper temprary credentials %+v", tc)
	}
}

func TestHMACEncode(t *testing.T) {
	s := `POST&http%3A%2F%2Fapi.t.sina.com.cn%2Foauth%2Frequest_token&oauth_body_hash%3D2jmj7l5rSw0yVb%252FvlWAYkK%252FYBwk%253D%26oauth_callback%3Dhttp%253A%252F%252Ffanliwuxian.com%252Fweibo%252Flogin%26oauth_consumer_key%3D3219312021%26oauth_nonce%3DCRG1tXMJXXabVnps0Q6mNqitupMYZxP5NstHavsLihE%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1331636489%26oauth_version%3D1.0`
	sign := digestAndEncode(hmac.New(sha1.New, []byte("b808b1c425062e95d30b8d30de7360c1&")), s)
	if sign != "mSd9QwtOHdis2PO7QM+OyWW8loc=" {
		t.Errorf("signature wrong for weibo %+v", sign)
	}
}

func TestQQHMacEncode(t *testing.T) {
	s := `GET&http%3A%2F%2Fopen.t.qq.com%2Fcgi-bin%2Frequest_token&oauth_callback%3Dhttp%253A%252F%252Ffanliwuxian.com%26oauth_consumer_key%3D801110457%26oauth_nonce%3D4560fa3aa611e4e80c50a997a4f0ff7a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1331688706%26oauth_version%3D1.0`
	sign := digestAndEncode(hmac.New(sha1.New, []byte("782a23e855269be5c0d8ab9fb21ed51e&")), s)
	if sign != "3PQHRTyfSWjd0LozMR6c+QrBrUo=" {
		t.Errorf("signature wrong for qq %+v", sign)
	}
}

func TestHashBody(t *testing.T) {
	body := ""
	body_hash := digestAndEncode(sha1.New(), body)
	if body_hash != "2jmj7l5rSw0yVb/vlWAYkK/YBwk=" {
		t.Errorf("wrong body hash", body_hash)
	}
}
