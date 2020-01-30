package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"strings"
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
	clientID     = "<CLIENT_ID>"
	clientSecret = "<CLIENT_SECRET>"
)

// 1-4. リダイレクトURIを定義
var RedirectURI = fmt.Sprintf("http://localhost:%d/callback", port)

const (
	// 1-5. OpenID ConnectのURLを定義
	oidcUrl = "https://auth.login.yahoo.co.jp"
)

var (
	// 1-6. テンプレートをレンダリング
	indexTemplate    = template.Must(template.ParseFiles("templates/index.html"))
	callbackTemplate = template.Must(template.ParseFiles("templates/callback.html"))
	errorTemplate    = template.Must(template.ParseFiles("templates/error.html"))
)

// 4-1. ランダム文字列を生成
func init() {
	rand.Seed(time.Now().UnixNano())
}

var randLetters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func generateRandomString() string {
	result := make([]rune, 32)
	for i := range result {
		result[i] = randLetters[rand.Intn(len(randLetters))]
	}
	return string(result)
}

// AuthorizationリクエストのURLを生成
func index(w http.ResponseWriter, r *http.Request) {
	log.Println("[[ login started ]]")
	// 4-2. セッションCookieに紐付けるstate値を生成し保存
	state := generateRandomString()
	stateCookie := &http.Cookie{
		Name:     "state",
		Value:    state,
		HttpOnly: true,
	}
	http.SetCookie(w, stateCookie)
	// 5-1. セッションCookieに紐付けるnonce値を生成し保存
	nonce := generateRandomString()
	nonceCookie := &http.Cookie{
		Name:     "nonce",
		Value:    nonce,
		HttpOnly: true,
	}
	http.SetCookie(w, nonceCookie)
	log.Println("stored state and nonce in session")

	// 1-7. AuthorizationリクエストURL生成
	u, err := url.Parse(oidcUrl)
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
	q.Set("client_id", clientID)
	q.Set("redirect_uri", RedirectURI)
	// 1-10. UserInfoエンドポイントから取得するscopeを指定
	q.Set("scope", "openid email")
	// 4-3. セッションCookieに紐づけたstate値を指定
	q.Set("state", state)
	// 5-2. セッションCookieに紐づけたnonce値を指定
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()
	log.Println("generated authorization endpoint url")
	// 1-11. 構造体にURLをセットしindex.htmlをレンダリング
	w.WriteHeader(http.StatusOK)
	indexTemplate.Execute(w, u.String())
}

// 2-3. TokenエンドポイントのJSONレスポンスの結果を格納する構造体
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IdToken      string `json:"id_token"`
}

// 3-2. UserInfoエンドポイントのJSONレスポンスの結果を格納する構造体
type UserInfoResponse struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
}

// 5-5. ID Tokenのヘッダーを格納する構造体
type IDTokenHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

// 5-10. JWKsエンドポイントのJSONレスポンスの結果を格納する構造体
type JWKsResponse struct {
	KeySets []struct {
		KeyID     string `json:"kid"`
		KeyType   string `json:"kty"`
		Algorithm string `json:"alg"`
		Use       string `json:"use"`
		Modulus   string `json:"n"`
		Exponent  string `json:"e"`
	} `json:"keys"`
}

// 5-16. ID Tokenのペイロードを格納する構造体
type IDTokenPayload struct {
	Issuer                        string   `json:"iss"`
	Subject                       string   `json:"sub"`
	Audience                      []string `json:"aud"`
	Expiration                    int      `json:"exp"`
	IssueAt                       int      `json:"iat"`
	AuthTime                      int      `json:"auth_time"`
	Nonce                         string   `json:"nonce"`
	AuthenticationMethodReference []string `json:"amr"`
	AccessTokenHash               string   `json:"at_hash"`
}

// Access Tokenの取得、ID Tokenの取得と検証
// UserInfoエンドポイントからユーザー属性情報の取得
func callback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// 4-4. redirect_uriからstate値の抽出
	stateQuery, ok := query["state"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		errorTemplate.Execute(w, "state query not found")
		return
	}
	state := stateQuery[0]
	storedState, err := r.Cookie("state")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		errorTemplate.Execute(w, "state cookie error")
		return
	}
	// 4-5. セッションCookieに紐づけていたstate値の破棄
	stateCookie := &http.Cookie{
		Name:   "state",
		MaxAge: -1,
	}
	http.SetCookie(w, stateCookie)

	// 4-6. state値の検証
	if state != storedState.Value {
		w.WriteHeader(http.StatusBadRequest)
		errorTemplate.Execute(w, "state does not match stored one")
		return
	}
	log.Println("success to verify state")

	// 2-1. Tokenリクエスト
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Add("client_id", clientID)
	values.Add("client_secret", clientSecret)
	values.Add("redirect_uri", RedirectURI)
	// 2-2. redirect_uriからAuthorization Codeを抽出
	values.Add("code", query["code"][0])
	tokenResponse, err := http.Post(oidcUrl+"/yconnect/v2/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(values.Encode()))

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to post request")
		return
	}
	defer func() {
		_, err = io.Copy(ioutil.Discard, tokenResponse.Body)
		if err != nil {
			log.Panic(err)
		}
		err = tokenResponse.Body.Close()
		if err != nil {
			log.Panic(err)
		}
	}()

	// 2-4. Tokenレスポンスを構造体に格納
	var tokenData TokenResponse
	err = json.NewDecoder(tokenResponse.Body).Decode(&tokenData)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to read token's json body")
		return
	}
	log.Println("requested token endpoint")

	// 5-3. ID Tokenのデータ部の分解
	idTokenParts := strings.SplitN(tokenData.IdToken, ".", 3)
	log.Println("header: ", idTokenParts[0])
	log.Println("payload: ", idTokenParts[1])
	log.Println("signature: ", idTokenParts[2])

	// 5-4. ID Tokenのヘッダーの検証
	header, err := base64.RawURLEncoding.DecodeString(idTokenParts[0])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to decode ID Token")
		return
	}
	// 5-6. ID Tokenのヘッダーを構造体に格納
	var idTokenHeader IDTokenHeader
	err = json.Unmarshal(header, &idTokenHeader)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to decode ID Token")
		return
	}
	log.Println("typ: ", idTokenHeader.Type)
	log.Println("alg: ", idTokenHeader.Algorithm)

	// 5-7. typ値の検証
	if idTokenHeader.Type != "JWT" {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "invalid id token type")
		return
	}
	// 5-8. alg値の検証
	if idTokenHeader.Algorithm != "RS256" {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "invalid id token algorithm")
		return
	}

	// 5-9. JWKsリクエスト
	jwksResponse, err := http.Get(oidcUrl + "/yconnect/v2/jwks")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to get jwk")
		return
	}
	defer func() {
		_, err = io.Copy(ioutil.Discard, jwksResponse.Body)
		if err != nil {
			log.Panic(err)
		}
		err = jwksResponse.Body.Close()
		if err != nil {
			log.Panic(err)
		}
	}()

	// 5-11. JWKsレスポンスを構造体に格納
	var jwksData JWKsResponse
	err = json.NewDecoder(jwksResponse.Body).Decode(&jwksData)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to read jwk's json body")
		return
	}
	log.Println("requested jwks endpoint")

	// 5-12. modulus値とexponent値の抽出
	var modulus, exponent string
	for _, keySet := range jwksData.KeySets {
		if keySet.KeyID == idTokenHeader.KeyID {
			log.Println("kid: " + keySet.KeyID)
			if keySet.KeyType != "RSA" || keySet.Algorithm != idTokenHeader.Algorithm || keySet.Use != "sig" {
				w.WriteHeader(http.StatusUnauthorized)
				errorTemplate.Execute(w, "invalid kid, alg or use")
				return
			}
			modulus = keySet.Modulus
			exponent = keySet.Exponent
			break
		}
	}
	log.Println("modulus: ", modulus)
	log.Println("exponent: ", exponent)
	if modulus == "" || exponent == "" {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to extract modulus or exponent")
		return
	}
	log.Println("extracted modulus and exponent")

	// 5-13. n(modulus)とe(exponent)から公開鍵を生成
	decodedModulus, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to decode modulus")
		return
	}
	decodedExponent, err := base64.StdEncoding.DecodeString(exponent)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to decode exponent")
		return
	}
	var exponentBytes []byte
	if len(decodedExponent) < 8 {
		exponentBytes = make([]byte, 8-len(decodedExponent), 8)
		exponentBytes = append(exponentBytes, decodedExponent...)
	} else {
		exponentBytes = decodedExponent
	}
	reader := bytes.NewReader(exponentBytes)
	var e uint64
	err = binary.Read(reader, binary.BigEndian, &e)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to read binary exponent")
		return
	}
	generatedPublicKey := rsa.PublicKey{N: big.NewInt(0).SetBytes(decodedModulus), E: int(e)}
	log.Println("generated public key: ", generatedPublicKey)
	log.Println("generated public key from n and e")

	// 5-14. ID Tokenの署名を検証
	decodedSignature, err := base64.RawURLEncoding.DecodeString(idTokenParts[2])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to decode signature")
		return
	}

	hash := crypto.Hash.New(crypto.SHA256)
	_, err = hash.Write([]byte(idTokenParts[0] + "." + idTokenParts[1]))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to create id token hash")
		return
	}
	hashed := hash.Sum(nil)

	err = rsa.VerifyPKCS1v15(&generatedPublicKey, crypto.SHA256, hashed, decodedSignature)
	if err != nil {
		log.Println("failed to verify signature")
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to verify signature")
		return
	}
	log.Println("success to verify signature")

	// 5-15. ID Tokenのペイロードをデコード
	decodedPayload, err := base64.RawURLEncoding.DecodeString(idTokenParts[1])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to decode payload")
		return
	}

	// 5-17. ID Tokenのペイロードを構造体へ格納
	idTokenPayload := new(IDTokenPayload)
	err = json.Unmarshal(decodedPayload, idTokenPayload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to parse payload json")
		return
	}

	// 5-18. issuer値の検証
	log.Println("id token issuer: ", idTokenPayload.Issuer)
	if idTokenPayload.Issuer != oidcUrl+"/yconnect/v2" {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "mismatched issuer")
		return
	}
	log.Println("success to verify issuer")

	// 5-19. audience値の検証
	log.Println("id token audience: ", idTokenPayload.Audience)
	var isValidAudience bool
	for _, audience := range idTokenPayload.Audience {
		if audience == clientID {
			log.Println("mached audience: ", audience)
			isValidAudience = true
			break
		}
	}

	if !isValidAudience {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "mismatched audience")
		return
	}
	log.Println("success to verify audience")

	// 5-20. セッションCookieからnonce値の抽出
	storedNonce, err := r.Cookie("nonce")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		errorTemplate.Execute(w, "nonce cookie error")
		return
	}
	// 5-21. セッションCookieに紐づけていたnonce値の破棄
	nonceCookie := &http.Cookie{
		Name:   "nonce",
		MaxAge: -1,
	}
	http.SetCookie(w, nonceCookie)
	log.Println("id token nonce: ", idTokenPayload.Nonce)
	log.Println("stored nonce: ", storedNonce.Value)

	if idTokenPayload.Nonce != storedNonce.Value {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "nonce does not match stored one")
		return
	}
	log.Println("success to verify nonce")

	// 5-22. iat値の検証
	log.Println("id token iat: ", idTokenPayload.IssueAt)
	if int(time.Now().Unix())-idTokenPayload.IssueAt >= 600 {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "too far away from current time")
		return
	}
	log.Println("success to verify issue at")

	// 5-23. at_hash値の検証
	receivedAccessTokenHash := sha256.Sum256([]byte(tokenData.AccessToken))
	halfOfAccessTokenHash := receivedAccessTokenHash[:len(receivedAccessTokenHash)/2]
	encodedhalfOfAccessTokenHash := base64.RawURLEncoding.EncodeToString(halfOfAccessTokenHash)
	log.Println("id token at_hash: ", idTokenPayload.AccessTokenHash)
	log.Println("generated at_hash: ", encodedhalfOfAccessTokenHash)
	if idTokenPayload.AccessTokenHash != encodedhalfOfAccessTokenHash {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "mismatched at_hash")
		return
	}
	log.Println("success to verify at_hash")

	// 5-24. 以下の値の検証および利用は任意
	// - idTokenPayload.Expiration
	// - idTokenPayload.AuthTime
	// - idTokenPayload.AuthenticationMethodReference

	log.Println("success to verify id token claims")

	// 3-1. UserInfoリクエスト
	userInfoRequest, err := http.NewRequest(
		"POST",
		"https://userinfo.yahooapis.jp/yconnect/v2/attribute",
		nil,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to create user attribute request")
		return
	}
	userInfoRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	userInfoRequest.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	userInfoResponse, err := http.DefaultClient.Do(userInfoRequest)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to user attribute request")
		return
	}
	defer func() {
		_, err = io.Copy(ioutil.Discard, userInfoResponse.Body)
		if err != nil {
			log.Panic(err)
		}
		err = userInfoResponse.Body.Close()
		if err != nil {
			log.Panic(err)
		}
	}()

	// 3-3. UserInfoレスポンスを構造体に格納
	var userInfoData UserInfoResponse
	err = json.NewDecoder(userInfoResponse.Body).Decode(&userInfoData)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "failed to parse user info json")
		return
	}
	log.Println("requested userinfo endpoint")

	// 5-25. sub値の検証
	log.Println("id token sub: ", idTokenPayload.Subject)
	log.Println("userinfo sub: ", userInfoData.Subject)
	if idTokenPayload.Subject != userInfoData.Subject {
		w.WriteHeader(http.StatusInternalServerError)
		errorTemplate.Execute(w, "mismatched user id")
		return
	}
	log.Println("success to verify user id")

	// 3-4. 構造体にユーザー属性情報をセットしcallback.htmlをレンダリング
	w.WriteHeader(http.StatusOK)
	callbackTemplate.Execute(w, userInfoData)
	log.Println("[[ login completed ]]")
}
