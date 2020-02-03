package config

import "fmt"

const (
	Port = 8080
)

// 1-3. Client ID、Client Secretを定義
const (
	ClientID     = "<CLIENT_ID>"
	ClientSecret = "<CLIENT_SECRET>"
)

// 1-4. リダイレクトURIを定義
var RedirectURI = fmt.Sprintf("http://localhost:%d/callback", Port)

// 1-5. OpenID ConnectのURLを定義
const (
	OIDCURL = "https://auth.login.yahoo.co.jp"
)
