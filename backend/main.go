package main

import (
	"fmt"
	"net/http"
	"os"
)

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Healthy"))
}

func serverHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello welcome to my server!"))
}

func main() {
	fmt.Println("Hello, World!")
	// listen to port 8080
	http.HandleFunc("/", serverHandler)
	http.HandleFunc("/health", healthCheckHandler)

	port := os.Getenv("PORT")
	fmt.Println("Listening on port " + port + "...")
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Println("Error:", err)
	}
}
