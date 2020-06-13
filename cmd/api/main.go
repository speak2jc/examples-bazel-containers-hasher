package main

import (
    "encoding/json"
    "log"
    "net/http"
    "time"

    "github.com/gorilla/mux"
    "golang.org/x/crypto/bcrypt"
)

func main() {
    r := mux.NewRouter()
    r.HandleFunc("/hash", hashHandler).Methods(http.MethodPost)
    r.HandleFunc("/compare", compareHandler).Methods(http.MethodPost)

    srv := &http.Server{
        Handler:      r,
        Addr:         ":8000",
        WriteTimeout: 1 * time.Second,
        ReadTimeout:  1 * time.Second,
    }

    log.Println("Start serving...")
    log.Fatal(srv.ListenAndServe())
}

type hashRequest struct {
    Plain string `json:"plain"`
}

type hashResponse struct {
    Hashed string `json:"hashed"`
}

func hashHandler(w http.ResponseWriter, r *http.Request) {
    req := hashRequest{}
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        log.Printf("Cannot decode hashRequest: %s", err.Error())
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    hashedBytes, err := bcrypt.GenerateFromPassword([]byte(req.Plain), bcrypt.DefaultCost)
    if err != nil {
        log.Printf("Cannot encrypt password: %s", err.Error())
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    resp, err := json.Marshal(hashResponse{Hashed: string(hashedBytes)})
    if err != nil {
        log.Printf("Cannot marshal response json: %s", err.Error())
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write(resp)
}

type compareRequest struct {
    Hashed    string `json:"hashed"`
    CompareTo string `json:"compare_to"`
}

func compareHandler(w http.ResponseWriter, r *http.Request) {
    req := compareRequest{}
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        log.Printf("Cannot decode compareRequest: %s", err.Error())
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(req.Hashed), []byte(req.CompareTo))
    // the only error we can have here is if there's not a match
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    w.WriteHeader(http.StatusOK)
}
