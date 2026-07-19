package main

import (
	"net/url"
	"strings"
)

func urlQuery(q string) string { return url.QueryEscape(q) }

// sqlStr returns a safely single-quoted ClickHouse string literal.
func sqlStr(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}
