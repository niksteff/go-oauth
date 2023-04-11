package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	ErrInvalidConfig error = fmt.Errorf("error auth config invalid")
)

type Config struct {
	Auth0 Auth0
}

type Auth0 struct {
	ClientId     string // auth0 client id
	Domain       string // auth0 domain
	ClientSecret string // auth0 application client secret
	CallbackURL  string // auth0 callback
	Audience     string // auth0 audience
}

type Authenticator struct {
	conf           Config
	provider       *oidc.Provider
	oAuthConfig    oauth2.Config
	SessionManager *scs.SessionManager
}

func NewAuthenticator(conf Config, sessionManager *scs.SessionManager) (*Authenticator, error) {
	// perform some basic config validation
	if conf.Auth0.Domain == "" {
		return nil, ErrInvalidConfig
	}
	if conf.Auth0.ClientId == "" {
		return nil, ErrInvalidConfig
	}
	if conf.Auth0.ClientSecret == "" {
		return nil, ErrInvalidConfig
	}
	if conf.Auth0.CallbackURL == "" {
		return nil, ErrInvalidConfig
	}

	provider, err := oidc.NewProvider(
		context.Background(),
		"https://"+conf.Auth0.Domain+"/",
	)
	if err != nil {
		return nil, fmt.Errorf("error creating new provider: %w", err)
	}

	oauthConf := oauth2.Config{
		ClientID:     conf.Auth0.ClientId,
		ClientSecret: conf.Auth0.ClientSecret,
		RedirectURL:  conf.Auth0.CallbackURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"}, // TODO: this should be looked on
	}

	return &Authenticator{
		conf:           conf,
		provider:       provider,
		oAuthConfig:    oauthConf,
		SessionManager: sessionManager,
	}, nil
}

func (a *Authenticator) IsAuthenticated(next http.Handler) http.Handler {
	// TODO: jwt sessions here
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO perform the authentication mechanism here
		// - just check if authenticated
		// - add a second route for roles?
		log.Print("not checking authentication but allowing through!")
		next.ServeHTTP(w, r)
	})
}

func (a *Authenticator) Login() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: store the state in the session
		url := a.oAuthConfig.AuthCodeURL("1234567890", oauth2.SetAuthURLParam("audience", a.conf.Auth0.Audience))
		http.Redirect(w, r, url, http.StatusFound)
	})
}

func (a *Authenticator) Callback() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exchange an authorization code for a token.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
		defer cancel()

		// TODO: check the state param for CSRF
		state := r.URL.Query().Get("state")
		if state == "" {
			log.Printf("empty state parameter is invalid. Expected %s.", "1234567890") // TODO:
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Failed to exchange an authorization code for a token."))
			return
		}

		if state != "1234567890" { // TODO:
			log.Printf("invalid state parameter. Expected %s but got %s", "todo", state)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Failed to exchange an authorization code for a token."))
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Failed to exchange an authorization code for a token."))
			return
		}

		token, err := a.oAuthConfig.Exchange(ctx, code)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Failed to exchange an authorization code for a token."))
			return
		}

		log.Printf("token: %s", token.AccessToken) // TODO: clean up
		idToken, err := a.VerifyIDToken(ctx, token)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Failed to verify token."))
			return
		}

		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		for k, v := range claims {
			log.Printf("claim %s: %v", k, v)
		}

		// claims->Subject // TODO: this as a user id? subject identifies the user

		// TODO: store the token in a session
		a.SessionManager.Put(r.Context(), "email", claims["email"])
		a.SessionManager.Put(r.Context(), "accessToken", token.AccessToken)

		// Redirect to logged in page.
		http.Redirect(w, r, "/test", http.StatusTemporaryRedirect)
	})
}

// VerifyIDToken verifies that an *oauth2.Token is a valid *oidc.IDToken.
func (a *Authenticator) VerifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token field in oauth2 token")
	}

	oidcConfig := &oidc.Config{
		ClientID: a.oAuthConfig.ClientID,
	}

	return a.provider.Verifier(oidcConfig).Verify(ctx, rawIDToken)
}

// VerifyRawToken will verify a JWT string against the current auth config.
func (a *Authenticator) VerifyRawToken(ctx context.Context, token string) (*oidc.IDToken, error) {
	oidcConfig := &oidc.Config{
		ClientID: a.conf.Auth0.Audience, // TODO: double check if the audience is correct here
	}

	idToken, err := a.provider.Verifier(oidcConfig).Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("error verifying raw token: %w", err)
	}

	return idToken, nil
}

func (a *Authenticator) GetClaimsFromToken(ctx context.Context, idToken *oidc.IDToken) (map[string]any, error) {
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("error unmarshaling claims from token: %w", err)
	}

	return claims, nil
}

func (a *Authenticator) CheckClaims(ctx context.Context, idToken *oidc.IDToken, requiredPermissions ...string) (bool, error) {
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return false, fmt.Errorf("error unmarshaling claims from token: %w", err)
	}

	log.Printf("claims: %+v", claims)

	// only if all permissions are present the result is true
	rawTokenPermissions := claims["permissions"].([]interface{})
	
	tokenPermissions := make([]string, len(rawTokenPermissions))
	for i, v := range rawTokenPermissions {
		tokenPermissions[i] = fmt.Sprint(v)
	}

	for _, requiredPermission := range requiredPermissions {
		isPresent := contains(tokenPermissions, requiredPermission)
		if !isPresent {
			return false, nil
		}
	}

	return true, nil
}

func contains[T comparable](data []T, search T) bool {
	for _, d := range data {
		if d == search {
			return true
		}
	}

	return false
}
