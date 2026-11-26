package main

// licserver — capa 3: servidor central de licencias con autorización MANUAL.
//
// Flujo:
//   1. Cliente:  POST /request {fingerprint, customer} → id, queda "pending".
//   2. Vendedor: GET /admin/pending  → ve las solicitudes.
//   3. Vendedor: POST /admin/approve/<id>?days=30  → firma y entrega la licencia.
//   4. Cliente:  GET /license/<id> (poll) → recibe la licencia firmada.
//
// La clave privada (vendor.key) vive SOLO en este servidor. El cliente solo
// envía su fingerprint (hash de máquina), no datos sensibles.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	keyPath string
	port    string
	dataDir string
	mu      sync.Mutex
	priv    ed25519.PrivateKey
)

type license struct {
	Fingerprint string `json:"fingerprint"`
	Expires     string `json:"expires"`
	Sig         string `json:"sig"`
}

type request struct {
	ID          string   `json:"id"`
	Fingerprint string   `json:"fingerprint"`
	Customer    string   `json:"customer"`
	Contact     string   `json:"contact"`
	Status      string   `json:"status"` // pending / approved / rejected
	License     *license `json:"license,omitempty"`
	Created     string   `json:"created"`
}

func main() {
	flag.StringVar(&keyPath, "key", "../vendor.key", "clave privada Ed25519 (hex)")
	flag.StringVar(&port, "port", "8443", "puerto")
	flag.StringVar(&dataDir, "data", "licserver-data", "directorio de estado")
	flag.Parse()

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatalf("data dir: %v", err)
	}
	b, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("clave privada: %v", err)
	}
	p, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(p) != ed25519.PrivateKeySize {
		log.Fatalf("clave privada inválida")
	}
	priv = ed25519.PrivateKey(p)

	http.HandleFunc("/request", hRequest)
	http.HandleFunc("/license/", hLicense)
	http.HandleFunc("/admin/pending", hPending)
	http.HandleFunc("/admin/approve/", hApprove)
	http.HandleFunc("/admin/reject/", hReject)
	log.Printf("licserver escuchando en :%s (data=%s)", port, dataDir)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func reqPath(id string) string { return filepath.Join(dataDir, id+".json") }

func loadReq(id string) (*request, error) {
	b, err := os.ReadFile(reqPath(id))
	if err != nil {
		return nil, err
	}
	var r request
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func saveReq(r *request) {
	b, _ := json.MarshalIndent(r, "", "  ")
	os.WriteFile(reqPath(r.ID), b, 0o600)
}

func hRequest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Fingerprint string `json:"fingerprint"`
		Customer    string `json:"customer"`
		Contact     string `json:"contact"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	if in.Fingerprint == "" {
		http.Error(w, "fingerprint requerido", 400)
		return
	}
	idb := make([]byte, 8)
	rand.Read(idb)
	req := &request{
		ID:          hex.EncodeToString(idb),
		Fingerprint: in.Fingerprint,
		Customer:    in.Customer,
		Contact:     in.Contact,
		Status:      "pending",
		Created:     time.Now().Format(time.RFC3339),
	}
	mu.Lock()
	saveReq(req)
	mu.Unlock()
	json.NewEncoder(w).Encode(map[string]string{"id": req.ID, "status": "pending"})
}

func hLicense(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/license/")
	mu.Lock()
	defer mu.Unlock()
	req, err := loadReq(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch req.Status {
	case "approved":
		json.NewEncoder(w).Encode(req.License)
	case "pending":
		w.WriteHeader(202)
		fmt.Fprintln(w, "pendiente de aprobación")
	case "rejected":
		w.WriteHeader(403)
		fmt.Fprintln(w, "rechazada")
	}
}

func hPending(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	entries, _ := os.ReadDir(dataDir)
	var out []request
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if rq, err := loadReq(strings.TrimSuffix(e.Name(), ".json")); err == nil && rq.Status == "pending" {
			out = append(out, *rq)
		}
	}
	json.NewEncoder(w).Encode(out)
}

func hApprove(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/approve/")
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		fmt.Sscanf(d, "%d", &days)
	}
	mu.Lock()
	defer mu.Unlock()
	req, err := loadReq(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	expires := time.Now().AddDate(0, 0, days).Format(time.RFC3339)
	sig := ed25519.Sign(priv, []byte(req.Fingerprint+"|"+expires))
	req.License = &license{Fingerprint: req.Fingerprint, Expires: expires, Sig: hex.EncodeToString(sig)}
	req.Status = "approved"
	saveReq(req)
	json.NewEncoder(w).Encode(req.License)
}

func hReject(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/reject/")
	mu.Lock()
	defer mu.Unlock()
	req, err := loadReq(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	req.Status = "rejected"
	saveReq(req)
	fmt.Fprintln(w, "rechazada")
}
