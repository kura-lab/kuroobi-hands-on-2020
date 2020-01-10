package main

import (
	"fmt"
	"net/http"
)

func handler(writer http.ResponseWriter, request *http.Request) {
	fmt.Fprintf(writer, "Hello OpenID Connect!")
}

func main() {
	http.HandleFunc("/index", handler)
	http.ListenAndServe(":8080", nil)
}
