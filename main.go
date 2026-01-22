package keycloakopenid

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

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
		Value:    "v1.0.9",
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

	msg := fmt.Sprintf("Long session path: %s\n", req.URL.Path)
	msg += fmt.Sprintf("Long session paths: %v\n", LongSessionPaths)

	rw.Write([]byte(msg))

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

func (k *keycloakAuth) verifyToken(token string) (bool, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: k.InsecureSkipVerify},
	}

	client := &http.Client{Transport: tr}

	data := url.Values{
		"token": {token},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		k.KeycloakURL.JoinPath(
			"realms",
			k.KeycloakRealm,
			"protocol",
			"openid-connect",
			"token",
			"introspect",
		).String(),
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(k.ClientID, k.ClientSecret)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var introspectResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&introspectResponse)
	if err != nil {
		return false, err
	}

	return introspectResponse["active"].(bool), nil
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
