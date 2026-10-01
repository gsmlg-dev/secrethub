package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/gsmlg-dev/secrethub/caddy-secrethub-pki"
)

func main() {
	caddycmd.Main()
}
