package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	router := http.NewServeMux()

	router.HandleFunc("POST /payment/webhook", handlePaymentWebhook)

	http.ListenAndServe(":3000", router)
}

type WebhookRequest struct {
	Amount  int    `json:"amount"`
	Message string `json:"message"`
}

func handlePaymentWebhook(w http.ResponseWriter, r *http.Request) {
	// var req WebhookRequest
	// if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println("we got all webhooked data!!!", req)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
}
