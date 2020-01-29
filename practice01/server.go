package main

import (
	"fmt"
	"net/http"
)

func main() {
	// 1-1. マルチプレクサにハンドラを登録

	// 1-2. サーバー設定

}

// 1-6. error.htmlに渡す構造体(エラー文言)

// 1-10. index.htmlに渡す構造体(AuthorizationリクエストURL)

// 1-3. Client ID、Client Secret、リダイレクトURIを設定

// AuthorizationリクエストのURLを生成
func index(writer http.ResponseWriter, request *http.Request) {
	fmt.Println("[[ login started ]]")

	// 1-4. AuthorizationリクエストURL生成

	// 1-5. 構造体にエラー文言を格納してerror.htmlをレンダリング

	// 1-7. response_typeにAuthorization Code Flowを指定

	// 1-8. UserInfoエンドポイントから取得するscopeを指定

	// 1-9. 構造体にURLをセットしindex.htmlをレンダリング

}

// Access Tokenの取得、ID Tokenの取得と検証
// UserInfoエンドポイントからユーザー属性情報の取得
func callback(writer http.ResponseWriter, request *http.Request) {
}

// 1-5. テンプレートをレンダリング
func renderTemplate(writer http.ResponseWriter, data interface{}, filename string) {
}
