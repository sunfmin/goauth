package services

import (
	"github.com/sunfmin/goauth"
)

var GOOGLE = &goauth.Configuration{
	RequestTokenURL:        "https://www.google.com/accounts/OAuthGetRequestToken",
	AccessTokenURL:         "https://www.google.com/accounts/OAuthGetAccessToken",
	AuthorizeURL:           "https://www.google.com/accounts/OAuthAuthorizeToken",
	UseAuthorizationHeader: true,
	UseBodyHash:            false,
	UserIdKey:              "name",
}
