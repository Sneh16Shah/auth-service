package main

import (
	"fmt"
	"net/http"
)

func healthCheckHandler(w http.ResponseWriter, r *http.Request){
	w.WriteHeader(http.StatusOK);
	w.Write([]byte("Healthy"));
}

func serverHandler(w http.ResponseWriter, r *http.Request){
	w.WriteHeader(http.StatusOK);
	w.Write([]byte("Hello welcome to my server!"));
}

func main() {
	fmt.Println("Hello, World!")
	// listen to port 8080
	http.HandleFunc("/", serverHandler);
	http.HandleFunc("/health", healthCheckHandler);
	fmt.Println("Listening on port 8080...")
    if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Error:", err)
	}
}