package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"path"
	"time"
)

const (
	port = 8080
)

func main() {
	// 1-1. マルチプレクサにハンドラを登録
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("http://localhost:%d/index", port), http.StatusMovedPermanently)
	})
	mux.HandleFunc("/index", index)
	mux.HandleFunc("/callback", callback)

	// 1-2. サーバー設定
	server := &http.Server{
		Addr:           fmt.Sprintf("0.0.0.0:%d", port),
		Handler:        mux,
		ReadTimeout:    time.Second * 10,
		WriteTimeout:   time.Second * 600,
		MaxHeaderBytes: 1 << 20, // 1MB
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

const (
	// 1-3. Client ID、Client Secretを定義
	ClientID     = "<CLIENT_ID>"
	ClientSecret = "<CLIENT_SECRET>"
)

// 1-4. リダイレクトURIを定義
var RedirectURI = fmt.Sprintf("http://localhost:%d/callback", port)

const (
	// 1-5. OpenID ConnectのURLを定義
	oidcURL = "https://auth.login.yahoo.co.jp"
)

var (
	// 1-6. テンプレートをレンダリング
	indexTemplate    = template.Must(template.ParseFiles("templates/index.html"))
	callbackTemplate = template.Must(template.ParseFiles("templates/callback.html"))
	errorTemplate    = template.Must(template.ParseFiles("templates/error.html"))
)

// 4-1. ランダム文字列を生成

// AuthorizationリクエストのURLを生成
func index(w http.ResponseWriter, r *http.Request) {
	log.Println("[[ login started ]]")
	// 4-2. セッションCookieに紐付けるstate値を生成し保存

	// 5-1. セッションCookieに紐付けるnonce値を生成し保存

	// 1-7. AuthorizationリクエストURL生成
	u, err := url.Parse(oidcURL)
	if err != nil {
		// 1-8. 構造体にエラー文言を格納してerror.htmlをレンダリング
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "url parse error")
		return
	}
	u.Path = path.Join(u.Path, "yconnect/v2/authorization")
	q := u.Query()
	// 1-9. response_typeにAuthorization Code Flowを指定
	q.Set("response_type", "code")
	q.Set("client_id", ClientID)
	q.Set("redirect_uri", RedirectURI)
	// 1-10. UserInfoエンドポイントから取得するscopeを指定
	q.Set("scope", "openid email")
	// 4-3. セッションCookieに紐づけたstate値を指定

	// 5-2. セッションCookieに紐づけたnonce値を指定
	q.Set("nonce", "NONCE_STUB")
	u.RawQuery = q.Encode()
	log.Println("generated authorization endpoint url")
	// 1-11. 構造体にURLをセットしindex.htmlをレンダリング
	w.WriteHeader(http.StatusOK)
	indexTemplate.Execute(w, u.String())
}

// 2-4. TokenエンドポイントのJSONレスポンスの結果を格納する構造体

// 3-2. UserInfoエンドポイントのJSONレスポンスの結果を格納する構造体

// 5-5. ID Tokenのヘッダーを格納する構造体

// 5-10. JWKsエンドポイントのJSONレスポンスの結果を格納する構造体

// 5-16. ID Tokenのペイロードを格納する構造体

// Access Tokenの取得、ID Tokenの取得と検証
// UserInfoエンドポイントからユーザー属性情報の取得
func callback(w http.ResponseWriter, r *http.Request) {
	// 2-1. クエリを取得

	// 4-4. redirect_uriからstate値の抽出

	// 4-5. セッションCookieに紐づけていたstate値の破棄

	// 4-6. state値の検証

	// 2-2. Tokenリクエスト

	// 2-3. redirect_uriからAuthorization Codeを抽出

	// 2-5. Tokenレスポンスを構造体に格納

	// 5-3. ID Tokenのデータ部の分解

	// 5-4. ID Tokenのヘッダーの検証

	// 5-6. ID Tokenのヘッダーを構造体に格納

	// 5-7. typ値の検証

	// 5-8. alg値の検証

	// 5-9. JWKsリクエスト

	// 5-11. JWKsレスポンスを構造体に格納

	// 5-12. modulus値とexponent値の抽出

	// 5-13. n(modulus)とe(exponent)から公開鍵を生成

	// 5-14. ID Tokenの署名を検証

	// 5-17. ID Tokenのペイロードを構造体へ格納

	// 5-18. issuer値の検証

	// 5-19. audience値の検証

	// 5-20. セッションCookieからnonce値の抽出

	// 5-21. セッションCookieに紐づけていたnonce値の破棄

	// 5-22. iat値の検証

	// 5-23. at_hash値の検証

	// 5-24. 以下の値の検証および利用は任意
	// - idTokenPayload.Expiration
	// - idTokenPayload.AuthTime
	// - idTokenPayload.AuthenticationMethodReference

	// 3-1. UserInfoリクエスト

	// 3-3. UserInfoレスポンスを構造体に格納

	// 5-25. sub値の検証

	// 3-4. 構造体にユーザー属性情報をセットしcallback.htmlをレンダリング
}
