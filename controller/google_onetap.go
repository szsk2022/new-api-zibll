package controller

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Google One Tap / Sign in with Google button (Google Identity Services).
//
// The browser obtains a Google-issued ID token via the GSI script and posts it
// here. The token is verified against Google's public JWKS (RS256), then the
// request follows the standard login-or-register path. Google OAuth through
// the Zibll agent cannot offer One Tap — One Tap requires the Google JS SDK to
// run on this origin with its own client id — so this is a standalone login
// channel configured by `GoogleOneTapClientId`.

const (
	googleOneTapJWKSURL    = "https://www.googleapis.com/oauth2/v3/certs"
	googleOneTapCacheTTL   = time.Hour
	googleOneTapMaxClockSkew = 2 * time.Minute
)

type googleJWKS struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

var googleJWKSCache struct {
	mu       sync.Mutex
	keys     map[string]*rsa.PublicKey
	fetched  time.Time
}

func googleFetchJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	googleJWKSCache.mu.Lock()
	defer googleJWKSCache.mu.Unlock()
	if googleJWKSCache.keys != nil && time.Since(googleJWKSCache.fetched) < googleOneTapCacheTTL {
		return googleJWKSCache.keys, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleOneTapJWKSURL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google jwks endpoint returned status %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var jwks googleJWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	if len(keys) == 0 {
		return nil, errors.New("google jwks contains no RSA keys")
	}
	googleJWKSCache.keys = keys
	googleJWKSCache.fetched = time.Now()
	return keys, nil
}

// googleFindJWKSKey returns the public key for kid, refreshing the cache when
// Google has rotated keys and the kid is unknown.
func googleFindJWKSKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	keys, err := googleFetchJWKS(ctx)
	if err != nil {
		return nil, err
	}
	if key, ok := keys[kid]; ok {
		return key, nil
	}
	googleJWKSCache.mu.Lock()
	googleJWKSCache.keys = nil
	googleJWKSCache.fetched = time.Time{}
	googleJWKSCache.mu.Unlock()
	keys, err = googleFetchJWKS(ctx)
	if err != nil {
		return nil, err
	}
	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, errors.New("google id token key not found")
}

type googleIDTokenClaims struct {
	Iss           string `json:"iss"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Exp           int64  `json:"exp"`
	Iat           int64  `json:"iat"`
	Nonce         string `json:"nonce"`
}

// googleVerifyIDToken validates the GSI credential: RS256 signature against
// Google's JWKS, issuer, audience and expiry.
func googleVerifyIDToken(ctx context.Context, credential string) (*googleIDTokenClaims, error) {
	clientID := strings.TrimSpace(common.GoogleOneTapClientID)
	if clientID == "" {
		return nil, errors.New("google one tap is not configured")
	}
	parts := strings.Split(credential, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid google id token format")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid google id token header")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errors.New("invalid google id token header")
	}
	if header.Alg != "RS256" {
		return nil, errors.New("unsupported google id token algorithm")
	}
	publicKey, err := googleFindJWKSKey(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid google id token signature encoding")
	}
	signedContent := []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(signedContent)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("google id token signature verification failed")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid google id token payload")
	}
	var claims googleIDTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, errors.New("invalid google id token payload")
	}
	issOK := claims.Iss == "accounts.google.com" || claims.Iss == "https://accounts.google.com"
	if !issOK {
		return nil, errors.New("unexpected google id token issuer")
	}
	if claims.Aud != clientID {
		return nil, errors.New("google id token audience mismatch")
	}
	now := time.Now()
	if claims.Exp > 0 && now.After(time.Unix(claims.Exp, 0).Add(googleOneTapMaxClockSkew)) {
		return nil, errors.New("google id token expired")
	}
	if claims.Sub == "" {
		return nil, errors.New("google id token subject is empty")
	}
	return &claims, nil
}

type googleOneTapRequest struct {
	Credential string `json:"credential"`
}

// GoogleOneTapLogin handles the GSI credential callback.
func GoogleOneTapLogin(c *gin.Context) {
	if strings.TrimSpace(common.GoogleOneTapClientID) == "" {
		common.ApiErrorT(c, "Google sign-in is not enabled by administrator")
		return
	}
	var request googleOneTapRequest
	if err := common.DecodeJson(c.Request.Body, &request); err != nil || strings.TrimSpace(request.Credential) == "" {
		common.ApiErrorT(c, "Invalid parameters")
		return
	}
	claims, err := googleVerifyIDToken(c.Request.Context(), request.Credential)
	if err != nil {
		common.SysError(common.LogText("[OAuth-GoogleOneTap] credential rejected: %s", err.Error()))
		common.ApiErrorT(c, "Google sign-in verification failed, please try again")
		return
	}

	user, err := model.GetUserByGoogleId(claims.Sub)
	if err == nil {
		if user.Status != common.UserStatusEnabled {
			common.ApiErrorT(c, "User has been banned")
			return
		}
		setupLogin(user, nil, c)
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		common.ApiError(c, err)
		return
	}

	// New account
	if !common.RegisterEnabled {
		common.ApiErrorT(c, "New user registration has been disabled by administrator")
		return
	}
	if claims.Email == "" || !claims.EmailVerified {
		common.ApiErrorT(c, "Google account email is not verified and cannot be used for registration")
		return
	}
	user = &model.User{
		Username:    "google_" + strconv.Itoa(model.GetMaxUserId()+1),
		DisplayName: claims.Name,
		Email:       model.NormalizeEmail(claims.Email),
		GoogleId:    claims.Sub,
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
	}
	if user.DisplayName == "" {
		user.DisplayName = "Google User"
	}
	if err := model.EnsureEmailAvailable(user.Email, 0); err != nil {
		if errors.Is(err, model.ErrEmailAlreadyTaken) {
			common.ApiErrorT(c, "Email address is already in use")
			return
		}
		common.ApiError(c, err)
		return
	}
	if err := user.Insert(0); err != nil {
		common.ApiError(c, err)
		return
	}
	setupLogin(user, nil, c)
}

