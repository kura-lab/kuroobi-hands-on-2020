package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"time"
)

func main() {
	// 1-1. マルチプレクサにハンドラを登録
	mux := http.NewServeMux()
	mux.HandleFunc("/index", index)
	mux.HandleFunc("/callback", callback)

	// 1-2. サーバー設定
	server := &http.Server{
		Addr:           "0.0.0.0:8080",
		Handler:        mux,
		ReadTimeout:    time.Duration(10 * int64(time.Second)),
		WriteTimeout:   time.Duration(600 * int64(time.Second)),
		MaxHeaderBytes: 1 << 20, // 1MB
	}
	server.ListenAndServe()
}

// 1-6. error.htmlに渡す構造体(エラー文言)
type Error struct {
	Error string
}

// 1-10. index.htmlに渡す構造体(AuthorizationリクエストURL)
type Index struct {
	AuthorizationUrl string
}

// 1-3. Client ID、Client Secret、リダイレクトURIを設定
const CLIENT_ID = "<CLIENT_ID>"
const CLIENT_SECRET = "<CLIENT_SECRET>"
const REDIRECT_URI = "http://localhost:8080/callback"

// AuthorizationリクエストのURLを生成
func index(writer http.ResponseWriter, request *http.Request) {
	fmt.Println("[[ login started ]]")

	// 1-4. AuthorizationリクエストURL生成
	authorizationEndpoint := "https://auth.login.yahoo.co.jp"
	u, err := url.Parse(authorizationEndpoint)
	if err != nil {
		// 1-5. 構造体にエラー文言を格納してerror.htmlをレンダリング
		e := Error{Error: "url parse error"}
		renderTemplate(writer, e, "error")
		return
	}
	u.Path = path.Join(u.Path, "yconnect/v2/authorization")
	q := u.Query()
	// 1-7. response_typeにAuthorization Code Flowを指定
	q.Set("response_type", "code")
	q.Set("client_id", CLIENT_ID)
	q.Set("redirect_uri", REDIRECT_URI)
	// 1-8. UserInfoエンドポイントから取得するscopeを指定
	q.Set("scope", "openid email")
	q.Set("nonce", "NONCE_STUB")
	u.RawQuery = q.Encode()
	fmt.Println("generated authorization endpoint url")
	// 1-9. 構造体にURLをセットしindex.htmlをレンダリング
	indexData := Index{AuthorizationUrl: u.String()}
	renderTemplate(writer, indexData, "index")
}

// 2-4. TokenエンドポイントのJSONレスポンスの結果を格納する構造体

// Access Tokenの取得、ID Tokenの取得と検証
// UserInfoエンドポイントからユーザー属性情報の取得
func callback(writer http.ResponseWriter, request *http.Request) {

	// 2-1. Tokenリクエスト

	// 2-2. redirect_uriからAuthorization Codeを抽出

	// 2-3. Tokenレスポンスを構造体に格納

	fmt.Println("[[ login completed ]]")
}

// 1-5. テンプレートをレンダリング
func renderTemplate(writer http.ResponseWriter, data interface{}, filename string) {
	templates := template.Must(template.ParseFiles("templates/" + filename + ".html"))
	templates.ExecuteTemplate(writer, filename, data)
}
