package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64" // Lisa see import
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3" // Vajalik LDAP operatsioonideks
	"golang.org/x/crypto/ssh"    // Vajalik avaliku võtme parsimiseks
)

// --- Konfiguratsioon (Keskkonnamuutujatest) ---

var (
	listenAddr                = getEnv("LISTEN_ADDR", ":8080")
	ldapHost                  = getEnv("LDAP_HOST", "ldap.example.com")
	ldapPort                  = getEnv("LDAP_PORT", "636") // 636 LDAPS jaoks, 389 LDAP+StartTLS/plain jaoks
	ldapUseTLS                = getEnvBool("LDAP_USE_TLS", true)
	ldapStartTLS              = getEnvBool("LDAP_STARTTLS", false)        // Kasuta StartTLS (kui ldapUseTLS=false ja port 389)
	ldapSkipTLSVerify         = getEnvBool("LDAP_SKIP_TLS_VERIFY", false) // !!! TOOTMISES PEAB OLEMA FALSE !!!
	ldapBaseDN                = getEnv("LDAP_BASE_DN", "dc=example,dc=com")
	ldapUserDNTemplate        = getEnv("LDAP_USER_DN_TEMPLATE", "uid=%s,ou=people,"+ldapBaseDN)         // %s asendatakse kasutajanimega parooliautentimisel
	ldapSearchFilterTemplate  = getEnv("LDAP_SEARCH_FILTER_TEMPLATE", "(uid=%s)")                       // %s asendatakse kasutajanimega otsingul
	ldapSshPublicKeyAttr      = getEnv("LDAP_SSH_PUBLIC_KEY_ATTR", "sshPublicKey")                      // Atribuut, mis sisaldab avalikke võtmeid
	ldapBindDN                = getEnv("LDAP_BIND_DN", "")                                              // Jäta tühjaks anonüümseks otsinguks või täida service-konto DN (nt "cn=service,dc=example,dc=com")
	ldapBindPassword          = getEnv("LDAP_BIND_PASSWORD", "")                                        // Service-konto parool
	configKeyPathBase         = getEnv("CONFIG_KEY_PATH_BASE", "/etc/containerssh/userkeys")            // Baastee kasutaja avalike võtmete failidele configserveri jaoks
	configKeyFilenameTemplate = getEnv("CONFIG_KEY_FILENAME_TEMPLATE", "%s.pub")                        // Failinime muster (%s = username)
	defaultDockerImage        = getEnv("DEFAULT_DOCKER_IMAGE", "containerssh/containerssh-guest-image") // Vaikimisi Docker image
	defaultShellCommand       = getEnv("DEFAULT_SHELL_COMMAND", "/bin/bash")                            // Vaikimisi kest konteineris
)

// Abifunktsioon keskkonnamuutujate lugemiseks vaikimisi väärtusega
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	log.Printf("Using fallback for env var %s: %s", key, fallback)
	return fallback
}

// Abifunktsioon boolean keskkonnamuutujate lugemiseks
func getEnvBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		return strings.ToLower(value) == "true" || value == "1"
	}
	log.Printf("Using fallback for env var %s: %t", key, fallback)
	return fallback
}

// --- LDAP Ühenduse loomine ---

func connectLDAP() (*ldap.Conn, error) {
	ldapURL := fmt.Sprintf("ldap://%s:%s", ldapHost, ldapPort)
	var conn *ldap.Conn
	var err error

	if ldapUseTLS {
		ldapURL = fmt.Sprintf("ldaps://%s:%s", ldapHost, ldapPort)
		// #nosec G402 -- Kasutaja saab kontrollida skip verify seadet. Tootmises peaks see olema false.
		tlsConfig := &tls.Config{InsecureSkipVerify: ldapSkipTLSVerify}
		conn, err = ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		conn, err = ldap.DialURL(ldapURL)
	}

	if err != nil {
		log.Printf("ERROR: Failed to connect to LDAP server %s: %v", ldapURL, err)
		return nil, err
	}

	// Kasuta StartTLS, kui see on seadistatud ja tavaline LDAP ühendus loodi
	if !ldapUseTLS && ldapStartTLS {
		// #nosec G402 -- Kasutaja saab kontrollida skip verify seadet. Tootmises peaks see olema false.
		tlsConfig := &tls.Config{InsecureSkipVerify: ldapSkipTLSVerify}
		log.Println("Attempting StartTLS...")
		err = conn.StartTLS(tlsConfig)
		if err != nil {
			conn.Close() // Sulge algne ühendus, kui StartTLS ebaõnnestub
			log.Printf("ERROR: Failed to start TLS with LDAP server %s: %v", ldapURL, err)
			return nil, err
		}
		log.Println("StartTLS successful.")
	}

	return conn, nil
}

// --- Autentimise Loogika ---

// Struktuur autentimisvastusele (sama mõlemale meetodile)
type AuthResponse struct {
	Success bool `json:"success"`
}

// --- Parooliautentimine (/password) ---

type PasswordAuthRequest struct {
	Username string `json:"username"`
	//	Password      string `json:"password"`
	PasswordBase64 string `json:"passwordBase64"` // Uus väli Base64 jaoks
	ConnectionID   string `json:"connectionId"`
	RemoteAddress  string `json:"remoteAddress"`
}

func authenticateUserWithPasswordLDAP(username string, password string) bool {
	log.Printf("Attempting LDAP password authentication for user: %s", username)
	if username == "" || password == "" {
		log.Println("LDAP password auth failed: Username or password empty.")
		return false
	}

	conn, err := connectLDAP()
	if err != nil {
		return false // Viga logiti juba connectLDAP funktsioonis
	}
	defer conn.Close()

	// Ehita kasutaja DN (Distinguished Name)
	userDN := fmt.Sprintf(ldapUserDNTemplate, ldap.EscapeFilter(username))
	log.Printf("Attempting to bind as DN: %s", userDN)

	// Proovi siduda (bind) kasutaja DN-i ja parooliga
	err = conn.Bind(userDN, password)
	if err != nil {
		// Kontrolli spetsiifilist viga LDAPResultInvalidCredentials
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
			log.Printf("LDAP password auth failed for user %s: Invalid credentials.", username)
		} else {
			log.Printf("ERROR: LDAP bind failed for user %s (DN: %s): %v", username, userDN, err)
		}
		return false
	}

	log.Printf("LDAP password authentication successful for user: %s", username)
	return true
}

func handlePasswordAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	// Kasuta seda kui soovid teada kas parool on korrektselt sisestatud. (logitakse parool base64 kujul!)
	//log.Printf("Received raw /password request body: %s", string(bodyBytes))

	var authReq PasswordAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		log.Printf("Error decoding /password request body: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	//log.Printf("Decoded /password request structure: %+v", authReq)
	// Logi ilma paroolita
	log.Printf("Decoded /password request structure for user %s from %s (ConnID: %s)",
		authReq.Username,
		authReq.RemoteAddress,
		authReq.ConnectionID)

	// --- Base64 Dekodeerimine ---
	var plainPassword string
	if authReq.PasswordBase64 != "" {
		decodedPassBytes, err := base64.StdEncoding.DecodeString(authReq.PasswordBase64)
		if err != nil {
			log.Printf("Error decoding Base64 password for user %s: %v", authReq.Username, err)
			// Saadame ikkagi tühja parooli edasi, mis põhjustab autentimise ebaõnnestumise
			// Või võiks siin ka otse Bad Request tagastada? Sõltub eelistusest.
			plainPassword = ""
		} else {
			plainPassword = string(decodedPassBytes)
			log.Printf("Successfully decoded Base64 password for user %s", authReq.Username)
		}
	} else {
		// Kui PasswordBase64 välja polnud (nt curl test), võiks siin vaadata vana Password välja, kui see alles jäeti.
		// plainPassword = authReq.Password // Kui vana väli on alles
		log.Printf("PasswordBase64 field was empty for user %s", authReq.Username)
		plainPassword = "" // Või kasuta authReq.Password, kui see alles
	}
	// --- /Base64 Dekodeerimine ---

	// Kasuta dekodeeritud parooli autentimiseks
	isAuthenticated := authenticateUserWithPasswordLDAP(authReq.Username, plainPassword) // <-- Kasuta plainPassword muutujat
	authResp := AuthResponse{Success: isAuthenticated}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(authResp); err != nil {
		log.Printf("Error encoding /password response: %v", err)
	}
}

// --- Avaliku Võtmega Autentimine (/pubkey) ---

//type PublicKeyDetails struct {
//	PublicKey string `json:"publicKey"`
//}

type PublicKeyAuthRequest struct {
	Username string `json:"username"`
	//	PublicKey     PublicKeyDetails `json:"publicKey"`
	PublicKey     string `json:"publicKey"` // <--- Muudetud: Nüüd on see string
	ConnectionID  string `json:"connectionId"`
	RemoteAddress string `json:"remoteAddress"`
}

func authenticateUserWithPublicKeyLDAP(username string, clientPublicKeyStr string) bool {
	log.Printf("Attempting LDAP public key authentication for user: %s", username)
	if username == "" || clientPublicKeyStr == "" {
		log.Println("LDAP public key auth failed: Username or public key empty.")
		return false
	}

	// 1. Parseeri kliendi saadetud võti
	clientKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(clientPublicKeyStr))
	if err != nil {
		log.Printf("Failed to parse client public key for user %s: %v", username, err)
		log.Printf("Received key string: %s", clientPublicKeyStr)
		return false
	}
	clientKeyBytes := clientKey.Marshal()
	log.Printf("Parsed client public key. Fingerprint: %s", ssh.FingerprintSHA256(clientKey))

	// 2. Ühendu LDAP-iga
	conn, err := connectLDAP()
	if err != nil {
		return false
	}
	defer conn.Close()

	// 3. Vajadusel seo service-kontoga (kui anonüümne otsing pole lubatud)
	if ldapBindDN != "" && ldapBindPassword != "" {
		log.Printf("Binding with service account: %s", ldapBindDN)
		err = conn.Bind(ldapBindDN, ldapBindPassword)
		if err != nil {
			log.Printf("ERROR: Failed to bind with service account %s: %v", ldapBindDN, err)
			return false
		}
		log.Println("Service account bind successful.")
	} else {
		log.Println("Attempting anonymous search (no service account bind).")
	}

	// 4. Otsi kasutajat ja tema avalikke võtmeid
	searchFilter := fmt.Sprintf(ldapSearchFilterTemplate, ldap.EscapeFilter(username))
	attributesToFetch := []string{ldapSshPublicKeyAttr, "dn"} // Küsi ka DN-i logimiseks

	searchRequest := ldap.NewSearchRequest(
		ldapBaseDN,
		ldap.ScopeWholeSubtree, // Otsi kogu alamkataloogist
		ldap.NeverDerefAliases, // Ära järgi aliaseid
		0,                      // Suuruse limiit (0 = piiramata)
		0,                      // Ajalimiit (0 = piiramata)
		false,                  // Ainult tüübid? Ei
		searchFilter,           // Otsingufilter
		attributesToFetch,      // Soovitud atribuudid
		nil,                    // Kontrollid (ei vaja)
	)

	log.Printf("Performing LDAP search with filter: %s, base: %s, requesting attrs: %v", searchFilter, ldapBaseDN, attributesToFetch)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Printf("ERROR: LDAP search failed for user %s (filter: %s): %v", username, searchFilter, err)
		return false
	}

	if len(sr.Entries) == 0 {
		log.Printf("LDAP public key auth failed: User %s not found with filter '%s'.", username, searchFilter)
		return false
	}
	if len(sr.Entries) > 1 {
		log.Printf("Warning: LDAP search for user %s returned multiple entries (%d). Using the first one.", username, len(sr.Entries))
	}

	userEntry := sr.Entries[0]
	ldapKeys := userEntry.GetAttributeValues(ldapSshPublicKeyAttr)
	log.Printf("Found user DN: %s. Found %d values for attribute '%s'.", userEntry.DN, len(ldapKeys), ldapSshPublicKeyAttr)

	if len(ldapKeys) == 0 {
		log.Printf("LDAP public key auth failed: User %s found (DN: %s), but no '%s' attribute values.", username, userEntry.DN, ldapSshPublicKeyAttr)
		return false
	}

	// 5. Võrdle kliendi võtit LDAP-ist leitud võtmetega
	for _, ldapKeyStr := range ldapKeys {
		ldapKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ldapKeyStr))
		if err != nil {
			log.Printf("Warning: Failed to parse public key from LDAP attribute for user %s (DN: %s). Key data: %s. Error: %v", username, userEntry.DN, ldapKeyStr, err)
			continue // Jäta see võti vahele ja proovi järgmist
		}
		ldapKeyBytes := ldapKey.Marshal()
		if bytes.Equal(clientKeyBytes, ldapKeyBytes) {
			log.Printf("LDAP public key authentication successful for user %s (Key fingerprint match: %s, Source DN: %s)", username, ssh.FingerprintSHA256(ldapKey), userEntry.DN)
			return true
		}
	}

	log.Printf("LDAP public key authentication failed for user %s: Provided key does not match any keys found in LDAP attribute '%s' for DN: %s.", username, ldapSshPublicKeyAttr, userEntry.DN)
	return false
}

func handlePublicKeyAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// ... (päringu keha lugemine ja logimine, kui soovid alles jätta) ...

	var authReq PublicKeyAuthRequest // Kasutab parandatud struktuuri
	// Dekodeeri päringu keha (loe see uuesti, kui logisid selle)
	// Näide, kui oled logimiseks keha lugenud:
	bodyBytes, _ := io.ReadAll(r.Body) // Vead on juba varem käsitletud, kui logisid
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	// --- Lõpp ---

	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		log.Printf("Error decoding /pubkey request body: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	// defer r.Body.Close() // Pole vaja, kui kasutasid NopCloser'it

	log.Printf("Decoded /pubkey request structure: %+v", authReq) // Logi uus struktuur

	// Kontrolli, kas PublicKey väli on olemas ja sisaldab võtit
	// Nüüd on see otse authReq.PublicKey
	if authReq.PublicKey == "" {
		log.Printf("Public key missing or empty in request for user %s", authReq.Username)
		http.Error(w, "Bad request: publicKey field is missing or empty", http.StatusBadRequest)
		return
	}

	// Kasuta otse authReq.PublicKey autentimisfunktsioonis
	isAuthenticated := authenticateUserWithPublicKeyLDAP(authReq.Username, authReq.PublicKey) // <--- Muudetud siin
	authResp := AuthResponse{Success: isAuthenticated}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(authResp); err != nil {
		log.Printf("Error encoding /pubkey response: %v", err)
	}
}

// --- Konfiguratsiooni Loogika (/config) ---

type ConfigRequest struct {
	Username     string `json:"username"`
	ConnectionID string `json:"connectionId"`
	SessionID    string `json:"sessionId"`
}

type DockerExecutionConfig struct {
	Image         string            `json:"image"`
	ContainerName string            `json:"containerName,omitempty"`
	Command       []string          `json:"cmd,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	RestartPolicy string            `json:"restartPolicy,omitempty"`
	// Lisada saab veel palju Dockeri seadeid
}

type BackendConfig struct {
	Docker *DockerExecutionConfig `json:"docker,omitempty"`
}

type ConfigResponse struct {
	Backend string        `json:"backend"`
	Config  BackendConfig `json:"config"`
}

// Genereerib kasutajapõhise konfiguratsiooni, lisades dünaamiliselt võtme failist
func generateUserConfig(username string, sessionID string) ConfigResponse {
	log.Printf("Generating config for user: %s, session: %s", username, sessionID)

	// Ehita tee kasutaja avaliku võtme failini
	keyFilename := fmt.Sprintf(configKeyFilenameTemplate, username)
	keyFullPath := fmt.Sprintf("%s/%s", configKeyPathBase, keyFilename)

	var userPublicKey = ""
	keyData, err := os.ReadFile(keyFullPath)
	if err != nil {
		// Kui faili ei leita, logime hoiatuse, aga jätkame ilma võtmeta
		log.Printf("Warning: Could not read public key file for user %s at %s: %v. Proceeding without dynamic key injection.", username, keyFullPath, err)
	} else {
		userPublicKey = strings.TrimSpace(string(keyData))
		if userPublicKey == "" {
			log.Printf("Warning: Public key file %s for user %s is empty.", keyFullPath, username)
		} else {
			log.Printf("Successfully read public key for user %s from %s", username, keyFullPath)
		}
	}

	// Konstrueeri baaskonfiguratsioon
	baseConfig := ConfigResponse{
		Backend: "docker",
		Config: BackendConfig{
			Docker: &DockerExecutionConfig{
				Image:         defaultDockerImage,
				ContainerName: "containerssh-" + sessionID,
				Env: map[string]string{
					"USER": username,
					// Siia saab lisada muid keskkonnamuutujaid
				},
				RestartPolicy: "no",
			},
		},
	}

	// Kui avalik võti leiti failist, muuda konteineri käivitamiskäsku
	if userPublicKey != "" {
		// Oluline: Peame tagama, et võti on käsurea jaoks ohutu (escape'ima erimärgid)
		// Siin lihtne näide, mis eeldab, et võti ei sisalda ' ega " märke.
		// Robustsem lahendus kasutaks proper shell escaping'ut.
		// Asendame lihtsad ülakomad, et vältida shelli segadust.
		escapedKey := strings.ReplaceAll(userPublicKey, "'", "'\\''")

		// Loo käsk, mis lisab võtme authorized_keys faili ja käivitab seejärel vaikimisi shelli
		// Kasutame `sh -c`, et mitu käsku käivitada.
		// Loome .ssh kausta ja seame õigused, kui neid pole.
		// Lisame võtme faili lõppu.
		// Käivitame lõpuks vaikimisi käsu (nt /bin/bash).
		injectionCommand := fmt.Sprintf(
			"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && exec %s",
			escapedKey,
			defaultShellCommand, // Käsk, mis käivitatakse pärast võtme lisamist
		)
		// Asenda konteineri Command/Cmd selle uue käsuga
		baseConfig.Config.Docker.Command = []string{"sh", "-c", injectionCommand}
		log.Printf("Injecting public key for user %s via modified container command.", username)
	} else {
		// Kui võtit ei lisata, kasutame lihtsalt vaikimisi shelli
		baseConfig.Config.Docker.Command = []string{defaultShellCommand}
	}

	log.Printf("Generated config for user %s: %+v", username, baseConfig)
	return baseConfig
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var configReq ConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&configReq); err != nil {
		log.Printf("Error decoding /config request body: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	userConfig := generateUserConfig(configReq.Username, configReq.SessionID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(userConfig); err != nil {
		log.Printf("Error encoding /config response: %v", err)
	}
}

// --- Main Funktsioon ---

func main() {
	// Logi konfiguratsioon käivitamisel (v.a paroolid)
	log.Println("--- Configuration ---")
	log.Printf("LISTEN_ADDR: %s", listenAddr)
	log.Printf("LDAP_HOST: %s", ldapHost)
	log.Printf("LDAP_PORT: %s", ldapPort)
	log.Printf("LDAP_USE_TLS: %t", ldapUseTLS)
	log.Printf("LDAP_STARTTLS: %t", ldapStartTLS)
	log.Printf("LDAP_SKIP_TLS_VERIFY: %t (!!! WARNING: Should be false in production !!!)", ldapSkipTLSVerify)
	log.Printf("LDAP_BASE_DN: %s", ldapBaseDN)
	log.Printf("LDAP_USER_DN_TEMPLATE: %s", ldapUserDNTemplate)
	log.Printf("LDAP_SEARCH_FILTER_TEMPLATE: %s", ldapSearchFilterTemplate)
	log.Printf("LDAP_SSH_PUBLIC_KEY_ATTR: %s", ldapSshPublicKeyAttr)
	log.Printf("LDAP_BIND_DN: %s", ldapBindDN)
	log.Printf("LDAP_BIND_PASSWORD: %s", "[REDACTED]") // Ära logi parooli
	log.Printf("CONFIG_KEY_PATH_BASE: %s", configKeyPathBase)
	log.Printf("CONFIG_KEY_FILENAME_TEMPLATE: %s", configKeyFilenameTemplate)
	log.Printf("DEFAULT_DOCKER_IMAGE: %s", defaultDockerImage)
	log.Printf("DEFAULT_SHELL_COMMAND: %s", defaultShellCommand)
	log.Println("---------------------")

	// Registreeri kõik HTTP käsitlejad
	http.HandleFunc("/password", handlePasswordAuth)
	http.HandleFunc("/pubkey", handlePublicKeyAuth)
	http.HandleFunc("/config", handleConfig)

	// Käivita server
	log.Printf("Starting combined Authentication and Configuration Server on %s", listenAddr)
	log.Println("Supported endpoints: /password, /pubkey, /config")
	server := &http.Server{
		Addr:         listenAddr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
