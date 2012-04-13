package goauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	// "math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var Verbose bool

type Configuration struct {
	RequestTokenURL        string
	AccessTokenURL         string
	AuthorizeURL           string
	Realm                  string
	UseAuthorizationHeader bool
	UseBodyHash            bool
	UserURL                string
	UserIdKey              string
}

// weibo: &{OAuthToken:20ff240e49bc8b6d62b56bca84334a6f OAuthTokenSecret:87c67d2e57225dd120d0d574473549a2 RawValues:map[oauth_token_secret:[87c67d2e57225dd120d0d574473549a2] oauth_token:[20ff240e49bc8b6d62b56bca84334a6f] user_id:[2660265991]]}
// qq: &{OAuthToken:c711e04e6d9c48a38c81f75edfb43109 OAuthTokenSecret:faf59685a91af9d94dae5165b35fa018 RawValues:map[oauth_token_secret:[faf59685a91af9d94dae5165b35fa018] oauth_token:[c711e04e6d9c48a38c81f75edfb43109] name:[fanliwuxian]]}

type Client struct {
	clientCredential *ClientCredential
	config           *Configuration
	Scope            string
	RequestMethod    string
}

type ClientCredential struct {
	Key    string
	Secret string
}

type TemporaryCredential struct {
	OAuthToken             string `bson:"_id"` // returned by /oauth/request_token
	OAuthSecret            string // returned by /oauth/request_token
	OAuthCallbackConfirmed bool   // returned by /oauth/request_token
	OAuthVerifier          string // returned by /oauth/authorize
}

type TokenCredential struct {
	OAuthToken       string // returned by /oauth/access_token
	OAuthTokenSecret string // returned by /oauth/access_token
	UserId           string
	UserInfo         map[string]interface{}
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

func (c *Client) GetAuthorizeURL(oauthCallback string) (authorizeUrl string, tc *TemporaryCredential, err error) {
	tc, err = c.GetTemporaryCredential(oauthCallback)
	if err != nil {
		return
	}

	q := url.Values{}
	q.Add("oauth_token", tc.OAuthToken)
	q.Add("oauth_callback", oauthCallback)
	authorizeUrl = fmt.Sprintf("%s?%s", c.config.AuthorizeURL, q.Encode())
	return
}

func (c *Client) GetTemporaryCredential(oauthCallback string) (r *TemporaryCredential, err error) {
	client := &http.Client{}
	req, err := http.NewRequest(c.requestMethodWithDefault(), c.config.RequestTokenURL, nil)
	if err != nil {
		return
	}

	c.signTemporaryRequest(req, oauthCallback, nil)
	values, err := doRequestAndParseError(client, req)

	r = &TemporaryCredential{OAuthSecret: values.Get("oauth_token_secret"), OAuthToken: values.Get("oauth_token")}
	return
}

func (c *Client) GetTokenCredential(tcWithVerifier *TemporaryCredential) (r *TokenCredential, err error) {
	client := &http.Client{}

	req, err := http.NewRequest(c.requestMethodWithDefault(), c.config.AccessTokenURL, nil)
	if err != nil {
		return
	}
	c.signTemporaryRequest(req, "", tcWithVerifier)
	values, err := doRequestAndParseError(client, req)
	if err != nil {
		return
	}
	r = &TokenCredential{
		OAuthToken:       values.Get("oauth_token"),
		OAuthTokenSecret: values.Get("oauth_token_secret"),
		UserId:           values.Get(c.config.UserIdKey),
	}
	if c.config.UserURL != "" {
		infoReq, err := http.NewRequest("GET", c.config.UserURL, nil)
		c.SignRequest(r, infoReq)
		resp, err := client.Do(infoReq)
		if err == nil {
			defer resp.Body.Close()

			b, _ := ioutil.ReadAll(resp.Body)
			json.Unmarshal(b, &r.UserInfo)
		}
	}

	return
}

func (c *Client) SignRequest(token *TokenCredential, req *http.Request) {
	c.signTemporaryRequest(req, "", &TemporaryCredential{OAuthToken: token.OAuthToken, OAuthSecret: token.OAuthTokenSecret})
}

func (c *Client) requestMethodWithDefault() string {
	m := c.RequestMethod
	if m == "" {
		m = "POST"
	}
	return m
}
func doRequestAndParseError(client *http.Client, req *http.Request) (values url.Values, err error) {
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if Verbose {
		log.Printf("goauth: request: %s\n", req.URL.String())
		log.Printf("goauth: response: %s\n", string(body))
	}
	values, err = url.ParseQuery(string(body))
	if err != nil {
		return
	}
	if len(values.Get("error")) > 0 {
		err = NewErrorFromValues(values)
		return
	}
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

func (c *Client) signTemporaryRequest(req *http.Request, oauthCallback string, tc *TemporaryCredential) {
	signvalues := NameValueSlice{}
	signvalues.Add("oauth_consumer_key", c.clientCredential.Key)
	signvalues.Add("oauth_signature_method", "HMAC-SHA1")
	signvalues.Add("oauth_timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	// signvalues.Add("oauth_nonce", fmt.Sprintf("%x", fmt.Sprintf("%s", rand.Int())))
	signvalues.Add("oauth_nonce", "90a198deebe36f9397eab61c2047481c")
	signvalues.Add("oauth_version", "1.0")
	if c.Scope != "" {
		signvalues.Add("scope", c.Scope)
	}

	if tc != nil {
		if tc.OAuthToken != "" {
			signvalues.Add("oauth_token", tc.OAuthToken)
		}
		if tc.OAuthVerifier != "" {
			signvalues.Add("oauth_verifier", tc.OAuthVerifier)
		}
	}

	authorizationvalues := signvalues.Clone()
	if oauthCallback != "" {
		signvalues.Add("oauth_callback", url.QueryEscape(oauthCallback))
		authorizationvalues.Add("oauth_callback", oauthCallback)
	}

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

	oauthsecret := ""
	if tc != nil {
		oauthsecret = tc.OAuthSecret
	}
	hmacKey := fmt.Sprintf("%s&%s", url.QueryEscape(c.clientCredential.Secret), url.QueryEscape(oauthsecret))
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
