package goauth

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type NameValueSlice [][]string

func (ns *NameValueSlice) Add(key string, value string) {
	*ns = append(*ns, []string{key, value})
	return
}

func (ns NameValueSlice) Clone() (r NameValueSlice) {
	for _, m := range ns {
		r = append(r, []string{m[0], m[1]})
	}
	return
}

func (ns NameValueSlice) Authorization() (r string) {
	var rs []string

	for _, m := range [][]string(ns) {
		rs = append(rs, fmt.Sprintf(`%s="%s"`, url.QueryEscape(m[0]), url.QueryEscape(m[1])))
	}
	sort.Strings(rs)
	return "OAuth " + strings.Join(rs, ", ")
}

func (ns NameValueSlice) NormalizedString() (r string) {
	var rs []string
	for _, m := range ns {
		rs = append(rs, fmt.Sprintf(`%s%s%s`, url.QueryEscape(m[0]), url.QueryEscape("="), url.QueryEscape(m[1])))
	}
	sort.Strings(rs)
	return strings.Join(rs, url.QueryEscape("&"))
}
