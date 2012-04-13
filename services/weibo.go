package services

import (
	"github.com/sunfmin/goauth"
)

var WEIBO = &goauth.Configuration{
	RequestTokenURL:        "http://api.t.sina.com.cn/oauth/request_token",
	AccessTokenURL:         "http://api.t.sina.com.cn/oauth/access_token",
	AuthorizeURL:           "http://api.t.sina.com.cn/oauth/authorize",
	UseAuthorizationHeader: true,
	UseBodyHash:            true,
	UserURL:                "http://api.t.sina.com.cn/account/verify_credentials.json",
	UserIdKey:              "user_id",
}
