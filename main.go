package keycloakopenid

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// JWK representa una clave del JWKS
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS representa el set de claves
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKSCache para cachear las claves públicas
type JWKSCache struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	mu        sync.RWMutex
}

// JWTHeader para parsear el header del JWT
type JWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// JWTClaims para validar los claims
type JWTClaims struct {
	Iss string      `json:"iss"`
	Aud interface{} `json:"aud"`
	Azp string      `json:"azp"`
	Exp int64       `json:"exp"`
	Iat int64       `json:"iat"`
}

var LongSessionPaths = []string{
	"/api/netsocs/dh/ws/v1/config_communication",
	"/api/netsocs/dh/objects",
}

var validateLongSessionURL = "http://netsocs-driverhub-service:3196/auth/validate"

func validateLongSession(token string) bool {

	req, err := http.NewRequest("POST", validateLongSessionURL, nil)
	if err != nil {
		return false
	}

	body, err := json.Marshal(map[string]string{
		"token": token,
	})
	if err != nil {
		return false
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (k *keycloakAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Añadir cookie de versión en todas las requests
	versionCookie := &http.Cookie{
		Name:     "plugin_version",
		Value:    "v1.0.14",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(rw, versionCookie)

	for _, substr := range k.IgnorePathPrefixes {
		if strings.Contains(req.URL.Path, substr) {
			k.next.ServeHTTP(rw, req)
			return
		}
	}

	for _, path := range LongSessionPaths {
		if strings.HasPrefix(req.URL.Path, path) {
			os.Stdout.WriteString(fmt.Sprintf("Long session path: %s\n", req.URL.Path))
			token := req.Header.Get("X-Auth-Token")
			if token == "" {
				rw.Write([]byte("No token found"))
				return
			}
			token = strings.TrimPrefix(token, "Bearer ")
			valid := validateLongSession(token)
			if !valid {
				rw.Write([]byte("Invalid token"))
				return
			}
			k.next.ServeHTTP(rw, req)
			return
		}
	}

	cookie, err := req.Cookie("Authorization")
	if err == nil && strings.HasPrefix(cookie.Value, "Bearer ") {
		token := strings.TrimPrefix(cookie.Value, "Bearer ")

		// Verifica si el token está expirado
		if isTokenExpired(token) {
			// Intenta refrescar el token si hay un refresh token
			refreshCookie, err := req.Cookie("RefreshToken")
			if err == nil && refreshCookie.Value != "" {
				newToken, err := k.refreshToken(refreshCookie.Value)
				if err == nil {
					// Actualiza el token en las cookies
					authCookie := &http.Cookie{
						Name:     "Authorization",
						Value:    "Bearer " + newToken,
						Secure:   true,
						HttpOnly: true,
						Path:     "/",
						SameSite: http.SameSiteLaxMode,
					}

					tokenCookie := &http.Cookie{
						Name:     k.TokenCookieName,
						Value:    newToken,
						Secure:   true,
						HttpOnly: true,
						Path:     "/",
						SameSite: http.SameSiteLaxMode,
					}

					http.SetCookie(rw, authCookie)
					http.SetCookie(rw, tokenCookie)

					// Actualiza el token actual
					token = newToken
				} else {
					// Si el refresh falla, redirige a keycloak
					k.redirectToKeycloak(rw, req)
					return
				}
			} else {
				// Si no hay refresh token, redirige a keycloak
				k.redirectToKeycloak(rw, req)
				return
			}
		}

		// Continúa con la verificación normal
		ok, err := k.verifyToken(token)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		if !ok {
			qry := req.URL.Query()
			qry.Del("code")
			qry.Del("state")
			qry.Del("session_state")
			req.URL.RawQuery = qry.Encode()
			req.RequestURI = req.URL.RequestURI()

			expiration := time.Now().Add(-24 * time.Hour)
			newCookie := &http.Cookie{
				Name:    "Authorization",
				Value:   "",
				Path:    "/",
				Expires: expiration,
				MaxAge:  -1,
			}
			http.SetCookie(rw, newCookie)

			k.redirectToKeycloak(rw, req)
			return
		}
		user, err := extractClaims(token, k.UserClaimName)
		if err == nil {
			req.Header.Set(k.UserHeaderName, user)
		}

		if k.UseAuthHeader {
			// Optionally set the Bearer token to the Authorization header.
			req.Header.Set("Authorization", "Bearer "+token)
		}

		k.next.ServeHTTP(rw, req)
	} else {
		authCode := req.URL.Query().Get("code")
		if authCode == "" {
			fmt.Printf("code is missing, redirect to keycloak\n")
			k.redirectToKeycloak(rw, req)
			return
		}

		stateBase64 := req.URL.Query().Get("state")
		if stateBase64 == "" {
			fmt.Printf("state is missing, redirect to keycloak\n")
			k.redirectToKeycloak(rw, req)
			return
		}

		fmt.Printf("exchange auth code called\n")
		token, refreshToken, err := k.exchangeAuthCode(req, authCode, stateBase64)
		fmt.Printf("exchange auth code finished %+v\n", token)
		if err != nil {
			// En caso de error, redirigir al hostname base
			scheme := req.Header.Get("X-Forwarded-Proto")
			host := req.Header.Get("X-Forwarded-Host")
			baseURL := fmt.Sprintf("%s://%s/", scheme, host)
			fmt.Printf("Error exchanging auth code, redirecting to base URL: %s\n", baseURL)
			http.Redirect(rw, req, baseURL, http.StatusTemporaryRedirect)
			return
		}

		if k.UseAuthHeader {
			// Optionally set the Bearer token to the Authorization header.
			req.Header.Set("Authorization", "Bearer "+token)
		}

		authCookie := &http.Cookie{
			Name:     "Authorization",
			Value:    "Bearer " + token,
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteLaxMode, // Allows requests originating from sibling domains (same parent diff sub domain) to access the cookie
		}

		tokenCookie := &http.Cookie{
			Name:     k.TokenCookieName, // Defaults to "AUTH_TOKEN"
			Value:    token,
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteLaxMode, // Allows requests originating from sibling domains (same parent diff sub domain) to access the cookie
		}

		http.SetCookie(rw, authCookie)
		req.AddCookie(authCookie) // Add the cookie to the request so it is present on the redirect and prevents infite loop of redirects.

		// Set the token to a default/custom cookie that doesnt require trimming the Bearer prefix for common integration compatibility
		http.SetCookie(rw, tokenCookie)
		req.AddCookie(tokenCookie) // Add the cookie to the request so it is present on the initial redirect below.

		// Añade una cookie para el refresh token
		refreshTokenCookie := &http.Cookie{
			Name:     "RefreshToken",
			Value:    refreshToken,
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(rw, refreshTokenCookie)

		qry := req.URL.Query()
		qry.Del("code")
		qry.Del("state")
		qry.Del("session_state")
		req.URL.RawQuery = qry.Encode()
		req.RequestURI = req.URL.RequestURI()

		scheme := req.Header.Get("X-Forwarded-Proto")
		host := req.Header.Get("X-Forwarded-Host")
		originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

		http.Redirect(rw, req, originalURL, http.StatusTemporaryRedirect)
	}
}

func extractClaims(tokenString string, claimName string) (string, error) {
	jwtContent := strings.Split(tokenString, ".")
	if len(jwtContent) < 3 {
		return "", fmt.Errorf("malformed jwt")
	}

	var jwtClaims map[string]interface{}
	decoder := base64.StdEncoding.WithPadding(base64.NoPadding)

	jwt_bytes, _ := decoder.DecodeString(jwtContent[1])
	if err := json.Unmarshal(jwt_bytes, &jwtClaims); err != nil {
		return "", err
	}

	if claimValue, ok := jwtClaims[claimName]; ok {
		return fmt.Sprintf("%v", claimValue), nil
	}
	return "", fmt.Errorf("missing claim %s", claimName)
}

func (k *keycloakAuth) exchangeAuthCode(req *http.Request, authCode string, stateBase64 string) (string, string, error) {
	stateBytes, _ := base64.StdEncoding.DecodeString(stateBase64)
	var state state
	err := json.Unmarshal(stateBytes, &state)
	if err != nil {
		return "", "", err
	}

	target := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"token",
	)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: k.InsecureSkipVerify}

	resp, err := http.PostForm(target.String(),
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {k.ClientID},
			"client_secret": {k.ClientSecret},
			"code":          {authCode},
			"redirect_uri":  {state.RedirectURL},
		})

	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", errors.New("received bad response from Keycloak: " + string(body))
	}

	var tokenResponse KeycloakTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return "", "", err
	}

	return tokenResponse.AccessToken, tokenResponse.RefreshToken, nil
}

func (k *keycloakAuth) redirectToKeycloak(rw http.ResponseWriter, req *http.Request) {
	// Verificar si es una llamada API
	isAPIRequest := req.Header.Get("Accept") == "application/json" ||
		req.Header.Get("X-Requested-With") == "XMLHttpRequest"

	if isAPIRequest {
		// Para llamadas API, devolver 401 y un header especial
		rw.Header().Set("X-Auth-Required", "true")
		rw.Header().Set("X-Auth-Location", k.getKeycloakAuthURL(req))
		http.Error(rw, "Authentication required", http.StatusUnauthorized)
		return
	}

	// Para peticiones normales, continuar con el redirect
	// Eliminar las cookies existentes
	cookies := []string{"Authorization", "RefreshToken", k.TokenCookieName}
	for _, cookieName := range cookies {
		http.SetCookie(rw, &http.Cookie{
			Name:    cookieName,
			Value:   "",
			Path:    "/",
			Expires: time.Now().Add(-24 * time.Hour),
			MaxAge:  -1,
		})
	}

	scheme := req.Header.Get("X-Forwarded-Proto")
	host := req.Header.Get("X-Forwarded-Host")
	originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

	state := state{
		RedirectURL: originalURL,
	}

	stateBytes, _ := json.Marshal(state)
	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)

	redirectURL := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"auth",
	)
	redirectURL.RawQuery = url.Values{
		"response_type": {"code"},
		"client_id":     {k.ClientID},
		"redirect_uri":  {originalURL},
		"state":         {stateBase64},
		"scope":         {k.Scope},
	}.Encode()

	http.Redirect(rw, req, redirectURL.String(), http.StatusTemporaryRedirect)
}

// Nueva función para obtener la URL de autenticación
func (k *keycloakAuth) getKeycloakAuthURL(req *http.Request) string {
	scheme := req.Header.Get("X-Forwarded-Proto")
	host := req.Header.Get("X-Forwarded-Host")
	originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

	state := state{
		RedirectURL: originalURL,
	}

	stateBytes, _ := json.Marshal(state)
	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)

	redirectURL := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"auth",
	)
	redirectURL.RawQuery = url.Values{
		"response_type": {"code"},
		"client_id":     {k.ClientID},
		"redirect_uri":  {originalURL},
		"state":         {stateBase64},
		"scope":         {k.Scope},
	}.Encode()

	return redirectURL.String()
}

// base64URLDecode decodes a base64url string without padding
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// parseRSAPublicKey converts a JWK to an RSA public key
func parseRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	// Decode modulus (n)
	nBytes, err := base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %v", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode exponent (e)
	eBytes, err := base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %v", err)
	}
	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// fetchJWKS fetches the JWKS from the endpoint
func (k *keycloakAuth) fetchJWKS() (*JWKS, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: k.InsecureSkipVerify},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	resp, err := client.Get(k.jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %v", k.jwksURI, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("JWKS endpoint %s returned status %d, body: %s", k.jwksURI, resp.StatusCode, string(body))
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS from %s: %v", k.jwksURI, err)
	}

	return &jwks, nil
}

// refreshJWKS updates the cache of public keys
func (k *keycloakAuth) refreshJWKS() error {
	jwks, err := k.fetchJWKS()
	if err != nil {
		return err
	}

	newKeys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Use == "sig" && (jwk.Alg == "" || jwk.Alg == "RS256") {
			pubKey, err := parseRSAPublicKey(jwk)
			if err != nil {
				continue // Skip keys that fail to parse
			}
			newKeys[jwk.Kid] = pubKey
		}
	}

	k.jwksCache.mu.Lock()
	k.jwksCache.keys = newKeys
	k.jwksCache.fetchedAt = time.Now()
	k.jwksCache.mu.Unlock()

	return nil
}

// getPublicKey returns a public key by kid, refreshing cache if necessary
func (k *keycloakAuth) getPublicKey(kid string) (*rsa.PublicKey, error) {
	k.jwksCache.mu.RLock()
	cacheAge := time.Since(k.jwksCache.fetchedAt)
	key, exists := k.jwksCache.keys[kid]
	cachedKids := make([]string, 0, len(k.jwksCache.keys))
	for k := range k.jwksCache.keys {
		cachedKids = append(cachedKids, k)
	}
	k.jwksCache.mu.RUnlock()

	// If key exists and cache is fresh (< 5 minutes), return it
	if exists && cacheAge < 5*time.Minute {
		return key, nil
	}

	// Refresh cache if expired or key not found
	if cacheAge >= 5*time.Minute || !exists {
		if err := k.refreshJWKS(); err != nil {
			// If refresh fails but we have a cached key, use it
			if exists {
				return key, nil
			}
			return nil, fmt.Errorf("failed to refresh JWKS and no cached key (jwksURI=%s, kid=%s): %v", k.jwksURI, kid, err)
		}

		// Try to get the key again after refresh
		k.jwksCache.mu.RLock()
		key, exists = k.jwksCache.keys[kid]
		cachedKids = make([]string, 0, len(k.jwksCache.keys))
		for k := range k.jwksCache.keys {
			cachedKids = append(cachedKids, k)
		}
		k.jwksCache.mu.RUnlock()

		if !exists {
			return nil, fmt.Errorf("key with kid %s not found in JWKS (jwksURI=%s, available kids=%v)", kid, k.jwksURI, cachedKids)
		}
	}

	return key, nil
}

// parseJWT parses a JWT and returns header, claims, and signature
func parseJWT(token string) (*JWTHeader, *JWTClaims, []byte, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, nil, "", errors.New("malformed JWT: expected 3 parts")
	}

	// Decode and parse header
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("failed to decode JWT header: %v", err)
	}
	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, nil, "", fmt.Errorf("failed to parse JWT header: %v", err)
	}

	// Decode and parse claims
	claimsBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("failed to decode JWT claims: %v", err)
	}
	var claims JWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, nil, nil, "", fmt.Errorf("failed to parse JWT claims: %v", err)
	}

	// Decode signature
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("failed to decode JWT signature: %v", err)
	}

	// Signed content is header.claims (without signature)
	signedContent := parts[0] + "." + parts[1]

	return &header, &claims, signature, signedContent, nil
}

// verifySignature verifies the RS256 signature
func verifySignature(signedContent string, signature []byte, pubKey *rsa.PublicKey) error {
	hash := sha256.Sum256([]byte(signedContent))
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
}

// validateClaims validates the JWT claims
func (k *keycloakAuth) validateClaims(claims *JWTClaims) error {
	now := time.Now().Unix()

	// Validate issuer
	if claims.Iss != k.expectedIssuer {
		return fmt.Errorf("invalid issuer: expected %s, got %s", k.expectedIssuer, claims.Iss)
	}

	// Validate audience (can be string or array)
	audValid := false
	switch aud := claims.Aud.(type) {
	case string:
		audValid = aud == k.expectedAudience
	case []interface{}:
		for _, a := range aud {
			if str, ok := a.(string); ok && str == k.expectedAudience {
				audValid = true
				break
			}
		}
	}
	// Also check azp (authorized party) as fallback
	if !audValid && claims.Azp == k.expectedAudience {
		audValid = true
	}
	if !audValid {
		return fmt.Errorf("invalid audience: expected %s, got aud=%v azp=%s", k.expectedAudience, claims.Aud, claims.Azp)
	}

	// Validate expiration (with 30 second tolerance)
	if claims.Exp < now-30 {
		return fmt.Errorf("token has expired (exp=%d, now=%d, diff=%ds)", claims.Exp, now, now-claims.Exp)
	}

	// Validate issued at (not in the future with 30 second tolerance)
	if claims.Iat > now+30 {
		return fmt.Errorf("token issued in the future (iat=%d, now=%d)", claims.Iat, now)
	}

	return nil
}

// verifyTokenLocally validates a JWT token locally using JWKS
func (k *keycloakAuth) verifyTokenLocally(token string) (bool, error) {
	// Parse the JWT
	header, claims, signature, signedContent, err := parseJWT(token)
	if err != nil {
		return false, fmt.Errorf("JWT parse error: %v", err)
	}

	// Verify algorithm is RS256
	if header.Alg != "RS256" {
		return false, fmt.Errorf("unsupported algorithm: %s (expected RS256)", header.Alg)
	}

	// Get the public key
	pubKey, err := k.getPublicKey(header.Kid)
	if err != nil {
		return false, fmt.Errorf("get public key error (kid=%s): %v", header.Kid, err)
	}

	// Verify signature
	if err := verifySignature(signedContent, signature, pubKey); err != nil {
		return false, fmt.Errorf("invalid signature (kid=%s, alg=%s): %v", header.Kid, header.Alg, err)
	}

	// Validate claims
	if err := k.validateClaims(claims); err != nil {
		return false, fmt.Errorf("claims validation error: %v", err)
	}

	return true, nil
}

func (k *keycloakAuth) verifyToken(token string) (bool, error) {
	return k.verifyTokenLocally(token)
}

func (k *keycloakAuth) refreshToken(refreshToken string) (string, error) {
	target := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"token",
	)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: k.InsecureSkipVerify},
	}
	client := &http.Client{Transport: tr}

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {k.ClientID},
		"client_secret": {k.ClientSecret},
		"refresh_token": {refreshToken},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		target.String(),
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", errors.New("received bad response from Keycloak refresh token: " + string(body))
	}

	var tokenResponse KeycloakTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}

func isTokenExpired(token string) bool {
	jwtContent := strings.Split(token, ".")
	if len(jwtContent) < 3 {
		return true
	}

	var jwtClaims map[string]interface{}
	decoder := base64.StdEncoding.WithPadding(base64.NoPadding)

	jwt_bytes, err := decoder.DecodeString(jwtContent[1])
	if err != nil {
		return true
	}

	if err := json.Unmarshal(jwt_bytes, &jwtClaims); err != nil {
		return true
	}

	// Verifica el campo exp (expiration time)
	if exp, ok := jwtClaims["exp"].(float64); ok {
		// Agrega margen de 30 segundos
		return time.Now().Unix() > int64(exp)-30
	}

	return true
}
