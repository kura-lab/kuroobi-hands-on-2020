package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"strings"
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

var randLetters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// 4-2. ランダム文字列を生成
func generateRandomString() string {
	rand.Seed(time.Now().UnixNano())
	result := make([]rune, 32)
	for i := range result {
		result[i] = randLetters[rand.Intn(len(randLetters))]
	}
	return string(result)
}

// 1-3. Client ID、Client Secret、リダイレクトURIを設定
const CLIENT_ID = "<CLIENT_ID>"
const CLIENT_SECRET = "<CLIENT_SECRET>"
const REDIRECT_URI = "http://localhost:8080/callback"

// AuthorizationリクエストのURLを生成
func index(writer http.ResponseWriter, request *http.Request) {
	fmt.Println("[[ login started ]]")
	// 4-1. セッションCookieに紐付けるstate値を生成し保存
	state := generateRandomString()
	stateCookie := &http.Cookie{
		Name:     "state",
		Value:    state,
		HttpOnly: true,
	}
	http.SetCookie(writer, stateCookie)

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
	// 4-3. セッションCookieに紐づけたstate値を指定
	q.Set("state", state)
	q.Set("nonce", "NONCE_STUB")
	u.RawQuery = q.Encode()
	fmt.Println("generated authorization endpoint url")
	// 1-9. 構造体にURLをセットしindex.htmlをレンダリング
	indexData := Index{AuthorizationUrl: u.String()}
	renderTemplate(writer, indexData, "index")
}

// 2-4. TokenエンドポイントのJSONレスポンスの結果を格納する構造体
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IdToken      string `json:"id_token"`
}

// 3-3. UserInfoエンドポイントのJSONレスポンスの結果を格納する構造体
type UserInfoResponse struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
}

// Access Tokenの取得、ID Tokenの取得と検証
// UserInfoエンドポイントからユーザー属性情報の取得
func callback(writer http.ResponseWriter, request *http.Request) {
	// 4-4. redirect_uriからstate値の抽出
	query := request.URL.Query()
	state := query["state"][0]
	storedState, err := request.Cookie("state")
	// 4-5. セッションCookieに紐づけていたstate値の破棄
	stateCookie := &http.Cookie{
		Name:   "state",
		MaxAge: -1,
	}
	http.SetCookie(writer, stateCookie)

	if err != nil {
		e := Error{Error: "state cookie error"}
		renderTemplate(writer, e, "error")
		return
	}
	// 4-6. state値の検証
	if state != storedState.Value {
		e := Error{Error: "state does not match stored one"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("success to verify state")

	// 2-1. Tokenリクエスト
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Add("client_id", CLIENT_ID)
	values.Add("client_secret", CLIENT_SECRET)
	values.Add("redirect_uri", REDIRECT_URI)
	// 2-2. redirect_uriからAuthorization Codeを抽出
	values.Add("code", query["code"][0])
	tokenRequest, err := http.NewRequest(
		"POST",
		"https://auth.login.yahoo.co.jp/yconnect/v2/token",
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		e := Error{Error: "new http request error"}
		renderTemplate(writer, e, "error")
		return
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenClient := &http.Client{}
	tokenResponse, err := tokenClient.Do(tokenRequest)
	if err != nil {
		e := Error{Error: "post request error"}
		renderTemplate(writer, e, "error")
		return
	}
	defer tokenResponse.Body.Close()

	tokenBody, err := ioutil.ReadAll(tokenResponse.Body)
	if err != nil {
		e := Error{Error: "read body error"}
		renderTemplate(writer, e, "error")
		return
	}

	// 2-3. Tokenレスポンスを構造体に格納
	tokenData := new(TokenResponse)
	err = json.Unmarshal(tokenBody, tokenData)
	if err != nil {
		e := Error{Error: "json parse error"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("requested token endpoint")

	// 3-1. UserInfoリクエスト
	userInfoRequest, err := http.NewRequest(
		"POST",
		"https://userinfo.yahooapis.jp/yconnect/v2/attribute",
		nil,
	)
	if err != nil {
		e := Error{Error: "new http request error"}
		renderTemplate(writer, e, "error")
		return
	}
	userInfoRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	userInfoRequest.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	client2 := &http.Client{}
	userInfoResponse, err := client2.Do(userInfoRequest)
	if err != nil {
		e := Error{Error: "post request error"}
		renderTemplate(writer, e, "error")
		return
	}
	defer userInfoResponse.Body.Close()

	userInfoBody, err := ioutil.ReadAll(userInfoResponse.Body)
	if err != nil {
		e := Error{Error: "read body error"}
		renderTemplate(writer, e, "error")
		return
	}

	// 3-2. UserInfoレスポンスを構造体に格納
	userInfoData := new(UserInfoResponse)
	err = json.Unmarshal(userInfoBody, userInfoData)
	if err != nil {
		e := Error{Error: "json parse error"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("requested userinfo endpoint")

	// 3-4. 構造体にユーザー属性情報をセットしcallback.htmlをレンダリング
	renderTemplate(writer, userInfoData, "callback")
	fmt.Println("[[ login completed ]]")
}

// 1-5. テンプレートをレンダリング
func renderTemplate(writer http.ResponseWriter, data interface{}, filename string) {
	templates := template.Must(template.ParseFiles("templates/" + filename + ".html"))
	templates.ExecuteTemplate(writer, filename, data)
}
