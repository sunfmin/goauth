package goauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"hash"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Configuration struct {
	RequestTokenURL        string
	AccessTokenURL         string
	AuthorizeURL           string
	Realm                  string
	UseAuthorizationHeader bool
	UseBodyHash            bool
}

type Client struct {
	clientCredential *ClientCredential
	config           *Configuration
}

type ClientCredential struct {
	Key    string
	Secret string
}

type TemporaryCredential struct {
	OAuthToken             string // returned by /oauth/request_token
	OAuthSecret            string // returned by /oauth/request_token
	OAuthCallbackConfirmed bool   // returned by /oauth/request_token
	OAuthVerifier          string // returned by /oauth/authorize
}

type TokenCredential struct {
	OAuthToken       string // returned by /oauth/access_token
	OAuthTokenSecret string // returned by /oauth/access_token
}

type Error struct {
	Code    string
	Message string
	Request string
}

func (err *Error) Error() string {
	return fmt.Sprintf("%s %s", err.Code, err.Message)
}

func NewErrorFromValues(values url.Values) *Error {
	return &Error{values.Get("error_code"), values.Get("error"), values.Get("request")}
}

func NewClient(consumerKey string, consumerSecret string, config *Configuration) (c *Client) {
	c = &Client{
		clientCredential: &ClientCredential{consumerKey, consumerSecret},
		config:           config,
	}
	return
}

func (c *Client) GetTemporaryCredential(oauthCallback string) (r *TemporaryCredential, err error) {
	client := &http.Client{}
	req, err := http.NewRequest("POST", c.config.RequestTokenURL, nil)
	if err != nil {
		return
	}

	c.signRequest(req, oauthCallback, nil)
	resp, err := client.Do(req)

	if err != nil {
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return
	}
	if len(values.Get("error")) > 0 {
		err = NewErrorFromValues(values)
		return
	}

	r = &TemporaryCredential{OAuthSecret: values.Get("oauth_token_secret"), OAuthToken: values.Get("oauth_token")}
	return
}

func (c *Client) GetTokenCredential(tcWithVerifier *TemporaryCredential) (r *TokenCredential, err error) {
	return
}

func digestAndEncode(h hash.Hash, input string) (r string) {
	h.Write([]byte(input))
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write(h.Sum(nil))
	encoder.Close()
	return buf.String()
}

func (c *Client) signRequest(req *http.Request, oauthCallback string, tc *TemporaryCredential) {
	signvalues := NameValueSlice{}
	signvalues.Add("oauth_consumer_key", c.clientCredential.Key)
	signvalues.Add("oauth_signature_method", "HMAC-SHA1")
	signvalues.Add("oauth_timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	signvalues.Add("oauth_nonce", fmt.Sprintf("%d", rand.Int63()))
	signvalues.Add("oauth_version", "1.0")

	authorizationvalues := signvalues.Clone()
	signvalues.Add("oauth_callback", url.QueryEscape(oauthCallback))
	authorizationvalues.Add("oauth_callback", oauthCallback)

	if c.config.UseBodyHash {
		bodyhash := ""
		if strings.ToLower(req.Header.Get("Content-Type")) != "application/x-www-form-urlencoded" {
			body := ``
			if req.Body != nil {
				bb, _ := ioutil.ReadAll(req.Body)
				body = string(bb)
			}
			bodyhash = digestAndEncode(sha1.New(), body)
			signvalues.Add("oauth_body_hash", url.QueryEscape(bodyhash))
		}

		if bodyhash != "" {
			authorizationvalues.Add("oauth_body_hash", bodyhash)
		}
	}

	query := req.URL.Query()

	for key, vals := range query {
		for _, val := range vals {
			signvalues.Add(key, val)
		}
	}

	normalizedString := fmt.Sprintf("%s&%s&%s", req.Method, url.QueryEscape(req.URL.String()), signvalues.NormalizedString())

	oauthverifier := ""
	if tc != nil {
		oauthverifier = tc.OAuthVerifier
	}
	hmacKey := fmt.Sprintf("%s&%s", url.QueryEscape(c.clientCredential.Secret), url.QueryEscape(oauthverifier))
	signature := digestAndEncode(hmac.New(sha1.New, []byte(hmacKey)), normalizedString)
	authorizationvalues.Add("oauth_signature", signature)

	if len(c.config.Realm) > 0 {
		authorizationvalues.Add("OAuth realm", c.config.Realm)
	}

	if c.config.UseAuthorizationHeader {
		req.Header.Add("Authorization", authorizationvalues.Authorization())

	} else {
		req.URL.RawQuery = authorizationvalues.Query().Encode()
	}
	req.Header.Add("User-Agent", "github.com/sunfmin/goauth")

}
