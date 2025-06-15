// File: server.go (BBRF API Server)
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var jwtKey []byte
var db *sql.DB

func main() {
	godotenv.Load()

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET not set in environment")
	}
	jwtKey = []byte(secret)
	
	db = connectDB()
	defer db.Close()

	r := mux.NewRouter()
	r.HandleFunc("/login", Login).Methods("POST")
	r.HandleFunc("/api/company", Authenticate(AddCompany)).Methods("POST")
	r.HandleFunc("/api/domains", Authenticate(HandleDomains)).Methods("GET")
	r.HandleFunc("/api/domains/add", Authenticate(AddDomains)).Methods("POST")
	r.HandleFunc("/api/domains/count", Authenticate(CountDomains)).Methods("GET")
	r.HandleFunc("/api/domains/show", Authenticate(ShowDomain)).Methods("GET")
	r.HandleFunc("/api/scope/in", Authenticate(HandleInScope)).Methods("POST")
	r.HandleFunc("/api/scope/out", Authenticate(HandleOutScope)).Methods("POST")
	r.HandleFunc("/api/scope/show", Authenticate(ShowScope)).Methods("GET")
	r.HandleFunc("/api/ip", Authenticate(HandleIPs)).Methods("POST")
	r.HandleFunc("/api/ip/list", Authenticate(ListIPs)).Methods("GET")
	r.HandleFunc("/api/asn/add", Authenticate(HandleASNs)).Methods("POST")
	r.HandleFunc("/api/asn/list", Authenticate(ListASNs)).Methods("GET")
	r.HandleFunc("/api/company/list", Authenticate(ListCompanies)).Methods("GET")

	headersOk := handlers.AllowedHeaders([]string{"Authorization", "Content-Type"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "POST"})

	fmt.Println("[+] API server running with TLS on :8443")
	http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", handlers.CORS(originsOk, headersOk, methodsOk)(r))
}

func connectDB() *sql.DB {
	host := os.Getenv("POSTGRES_HOST")
	if host == "" {
		host = "localhost"
	}
	dbname := os.Getenv("POSTGRES_DB")
	if dbname == "" {
		dbname = "subdomains_db"
	}
	user := os.Getenv("POSTGRES_USER")
	if user == "" {
		user = "postgres"
	}
	password := os.Getenv("POSTGRES_PASSWORD")
	if password == "" {
		password = "postgres"
	}
	port := os.Getenv("POSTGRES_PORT")
	if port == "" {
		port = "5432"
	}
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	if err = db.Ping(); err != nil {
		log.Fatalf("Database unreachable: %v", err)
	}
	return db
}

func Login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil || creds.Username == "" || creds.Password == "" {
		http.Error(w, "Invalid credentials", http.StatusBadRequest)
		return
	}

	expectedUser := os.Getenv("BBRF_USER")
	expectedPass := os.Getenv("BBRF_PASS")
	if expectedUser == "" {
		expectedUser = "yourusername"
	}
	if expectedPass == "" {
		expectedPass = "yourpassword"
	}

	if creds.Username != expectedUser || creds.Password != expectedPass {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(48 * time.Hour)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func AddCompany(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Company string `json:"company"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Company == "" {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	_, err := db.Exec(`INSERT INTO companies (name) VALUES ($1) ON CONFLICT DO NOTHING`, req.Company)
	if err != nil {
		http.Error(w, "Failed to insert company", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Company '%s' added.", req.Company)
}

// func HandleDomains(w http.ResponseWriter, r *http.Request) {
// 	company := r.URL.Query().Get("company")
// 	if company == "" {
// 		http.Error(w, "Missing company", http.StatusBadRequest)
// 		return
// 	}
//
// 	var companyID int
// 	err := db.QueryRow("SELECT id FROM companies WHERE name = $1", company).Scan(&companyID)
// 	if err != nil {
// 		http.Error(w, "Company not found", http.StatusNotFound)
// 		return
// 	}
//
// 	rows, err := db.Query("SELECT subdomain FROM subdomains WHERE company_id = $1", companyID)
// 	if err != nil {
// 		http.Error(w, "Failed to query domains", http.StatusInternalServerError)
// 		return
// 	}
// 	defer rows.Close()
//
// 	w.Header().Set("Content-Type", "text/plain")
// 	for rows.Next() {
// 		var domain string
// 		if err := rows.Scan(&domain); err == nil {
// 			fmt.Fprintln(w, domain)
// 		}
// 	}
// }

func AddDomains(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Company string `json:"company"`
		Domains string `json:"domains"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	var companyID int
	err := db.QueryRow("SELECT id FROM companies WHERE name = $1", req.Company).Scan(&companyID)
	if err != nil {
		http.Error(w, "Company not found", http.StatusNotFound)
		return
	}
	domains := strings.Fields(req.Domains)
	for _, domain := range domains {
		_, _ = db.Exec("INSERT INTO subdomains (company_id, subdomain) VALUES ($1, $2) ON CONFLICT DO NOTHING", companyID, domain)
	}
	w.Write([]byte("Domains added."))
}

func CountDomains(w http.ResponseWriter, r *http.Request) {
	company := r.URL.Query().Get("company")
	var companyID int
	err := db.QueryRow("SELECT id FROM companies WHERE name = $1", company).Scan(&companyID)
	if err != nil {
		http.Error(w, "Company not found", http.StatusNotFound)
		return
	}
	var count int
	db.QueryRow("SELECT COUNT(*) FROM subdomains WHERE company_id = $1", companyID).Scan(&count)
	fmt.Fprintf(w, "%d", count)
}

func ShowDomain(w http.ResponseWriter, r *http.Request) {
	company := r.URL.Query().Get("company")
	query := r.URL.Query().Get("q")
	countOnly := r.URL.Query().Get("count") == "true"

	var companyID int
	err := db.QueryRow("SELECT id FROM companies WHERE name = $1", company).Scan(&companyID)
	if err != nil {
		http.Error(w, "Company not found", http.StatusNotFound)
		return
	}

	rows, err := db.Query("SELECT subdomain FROM subdomains WHERE company_id = $1 AND subdomain LIKE $2", companyID, "%"+query+"%")
	if err != nil {
		http.Error(w, "Failed to query subdomains", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	if countOnly {
		count := 0
		for rows.Next() {
			count++
		}
		fmt.Fprintf(w, "%d", count)
		return
	}

	for rows.Next() {
		var d string
		rows.Scan(&d)
		fmt.Fprintln(w, d)
	}
}

func HandleInScope(w http.ResponseWriter, r *http.Request) {
	handleScopeInsert(w, r, true)
}

func HandleOutScope(w http.ResponseWriter, r *http.Request) {
	handleScopeInsert(w, r, false)
}

func handleScopeInsert(w http.ResponseWriter, r *http.Request, inScope bool) {
	var req struct {
		Company string `json:"company"`
		Domains string `json:"domains"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var companyID int
	err := db.QueryRow("SELECT id FROM companies WHERE name = $1", req.Company).Scan(&companyID)
	if err != nil {
		http.Error(w, "Company not found", http.StatusNotFound)
		return
	}
	domains := strings.Fields(req.Domains)
	for _, domain := range domains {
		_, _ = db.Exec("INSERT INTO scope_domains (company_id, domain, in_scope) VALUES ($1, $2, $3) ON CONFLICT (company_id, domain) DO UPDATE SET in_scope = $3", companyID, domain, inScope)
	}
	fmt.Fprintln(w, "Scope entries added.")
}

func HandleIPs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Company string `json:"company"`
		IPs     string `json:"ips"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var companyID int
	err := db.QueryRow("SELECT id FROM companies WHERE name = $1", req.Company).Scan(&companyID)
	if err != nil {
		http.Error(w, "Company not found", http.StatusNotFound)
		return
	}
	ips := strings.Fields(req.IPs)
	for _, ip := range ips {
		_, _ = db.Exec("INSERT INTO ips (company_id, address) VALUES ($1, $2) ON CONFLICT DO NOTHING", companyID, ip)
	}
	w.Write([]byte("IPs added."))
}

// Re-add ShowScope handler that was previously removed or not copied over
func ShowScope(w http.ResponseWriter, r *http.Request) {
	company := r.URL.Query().Get("company")
	scopeType := r.URL.Query().Get("type") // must be "in" or "out"

	if company == "" || (scopeType != "in" && scopeType != "out") {
		http.Error(w, "Invalid query parameters", http.StatusBadRequest)
		return
	}

	inScope := (scopeType == "in")
	var companyID int
	err := db.QueryRow("SELECT id FROM companies WHERE name = $1", company).Scan(&companyID)
	if err != nil {
		http.Error(w, "Company not found", http.StatusNotFound)
		return
	}

	rows, err := db.Query("SELECT domain FROM scope_domains WHERE company_id = $1 AND in_scope = $2", companyID, inScope)
	if err != nil {
		http.Error(w, "Failed to query scope", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err == nil {
			fmt.Fprintln(w, domain)
		}
	}
}

// func ListASNs(w http.ResponseWriter, r *http.Request) {
// 	company := r.URL.Query().Get("company")
// 	if company == "" {
// 		http.Error(w, "Missing company", http.StatusBadRequest)
// 		return
// 	}
//
// 	var companyID int
// 	err := db.QueryRow("SELECT id FROM companies WHERE name = $1", company).Scan(&companyID)
// 	if err != nil {
// 		http.Error(w, "Company not found", http.StatusNotFound)
// 		return
// 	}
//
// 	rows, err := db.Query("SELECT asn FROM asns WHERE company_id = $1", companyID)
// 	if err != nil {
// 		http.Error(w, "Failed to query ASNs", http.StatusInternalServerError)
// 		return
// 	}
// 	defer rows.Close()
//
// 	w.Header().Set("Content-Type", "text/plain")
// 	for rows.Next() {
// 		var asn string
// 		if err := rows.Scan(&asn); err == nil {
// 			fmt.Fprintln(w, asn)
// 		}
// 	}
// }

func HandleASNs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Company string `json:"company"`
		ASNs    string `json:"asns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Company == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var companyID int
	err := db.QueryRow("SELECT id FROM companies WHERE name = $1", req.Company).Scan(&companyID)
	if err != nil {
		http.Error(w, "Company not found", http.StatusNotFound)
		return
	}

	asns := strings.Fields(req.ASNs)
	for _, asn := range asns {
		_, _ = db.Exec(`INSERT INTO asns (company_id, asn) VALUES ($1, $2) ON CONFLICT DO NOTHING`, companyID, asn)
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("ASNs added."))
}

//	func ListIPs(w http.ResponseWriter, r *http.Request) {
//		company := r.URL.Query().Get("company")
//		if company == "" {
//			http.Error(w, "Missing company", http.StatusBadRequest)
//			return
//		}
//
//		var companyID int
//		err := db.QueryRow("SELECT id FROM companies WHERE name = $1", company).Scan(&companyID)
//		if err != nil {
//			http.Error(w, "Company not found", http.StatusNotFound)
//			return
//		}
//
//		rows, err := db.Query("SELECT address FROM ips WHERE company_id = $1", companyID)
//		if err != nil {
//			http.Error(w, "Failed to query IPs", http.StatusInternalServerError)
//			return
//		}
//		defer rows.Close()
//
//		w.Header().Set("Content-Type", "text/plain")
//		for rows.Next() {
//			var ip string
//			if err := rows.Scan(&ip); err == nil {
//				fmt.Fprintln(w, ip)
//			}
//		}
//	}
func ListCompanies(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT name FROM companies")
	if err != nil {
		http.Error(w, "Failed to query companies", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var companies []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			companies = append(companies, name)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(companies)
}

func ListASNs(w http.ResponseWriter, r *http.Request) {
	company := r.URL.Query().Get("company")
	if company == "" {
		http.Error(w, "Missing company", http.StatusBadRequest)
		return
	}

	var companyID int
	err := db.QueryRow("SELECT id FROM companies WHERE name = $1", company).Scan(&companyID)
	if err != nil {
		http.Error(w, "Company not found", http.StatusNotFound)
		return
	}

	rows, err := db.Query("SELECT asn FROM asns WHERE company_id = $1", companyID)
	if err != nil {
		http.Error(w, "Failed to query ASNs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var asns []string
	for rows.Next() {
		var asn string
		if err := rows.Scan(&asn); err == nil {
			asns = append(asns, asn)
		}
	}

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(asns)
	} else {
		for _, a := range asns {
			fmt.Fprintln(w, a)
		}
	}
}

func HandleDomains(w http.ResponseWriter, r *http.Request) {
	company := r.URL.Query().Get("company")
	if company == "" {
		http.Error(w, "Missing company", http.StatusBadRequest)
		return
	}

	var companyID int
	err := db.QueryRow("SELECT id FROM companies WHERE name = $1", company).Scan(&companyID)
	if err != nil {
		http.Error(w, "Company not found", http.StatusNotFound)
		return
	}

	rows, err := db.Query("SELECT subdomain FROM subdomains WHERE company_id = $1", companyID)
	if err != nil {
		http.Error(w, "Failed to query domains", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err == nil {
			domains = append(domains, d)
		}
	}

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(domains)
	} else {
		for _, d := range domains {
			fmt.Fprintln(w, d)
		}
	}
}

func ListIPs(w http.ResponseWriter, r *http.Request) {
	company := r.URL.Query().Get("company")
	if company == "" {
		http.Error(w, "Missing company", http.StatusBadRequest)
		return
	}

	var companyID int
	err := db.QueryRow("SELECT id FROM companies WHERE name = $1", company).Scan(&companyID)
	if err != nil {
		http.Error(w, "Company not found", http.StatusNotFound)
		return
	}

	rows, err := db.Query("SELECT address FROM ips WHERE company_id = $1", companyID)
	if err != nil {
		http.Error(w, "Failed to query IPs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil {
			ips = append(ips, ip)
		}
	}

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ips)
	} else {
		for _, ip := range ips {
			fmt.Fprintln(w, ip)
		}
	}
}
