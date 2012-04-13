package services

import (
	"github.com/sunfmin/goauth"
)

var QQ = &goauth.Configuration{
	RequestTokenURL:        "http://open.t.qq.com/cgi-bin/request_token",
	AccessTokenURL:         "http://open.t.qq.com/cgi-bin/access_token",
	AuthorizeURL:           "http://open.t.qq.com/cgi-bin/authorize",
	UseAuthorizationHeader: false,
	UseBodyHash:            false,
	UserURL:                "http://open.t.qq.com/api/user/info",
	UserIdKey:              "name",
}
