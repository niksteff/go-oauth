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

func (a *Authenticator) Protect(next http.Handler, requiredPermissions ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error

		// first, get the raw token from the requests session
		rawAccessToken := a.SessionManager.GetString(r.Context(), "accessToken")
		if rawAccessToken == "" {
			log.Print("unable to get raw access token from session manager")

			w.Header().Add("content-type", "text/plain")
			w.WriteHeader(http.StatusUnauthorized)
			_, err = w.Write([]byte("forbidden - unauthenticated"))
			if err != nil {
				log.Printf("error writing content: %s", err.Error())
				return
			}

			return
		}

		log.Printf("accessToken: %s", rawAccessToken) // TODO: clean up

		// second, check the token for validity
		idToken, err := a.VerifyRawToken(r.Context(), rawAccessToken)
		if err != nil {
			log.Printf("forbidden - error verifying token in secured route: %s", err.Error())

			w.Header().Add("content-type", "text/plain")
			w.WriteHeader(http.StatusUnauthorized)
			_, err := w.Write([]byte(fmt.Sprintf("forbidden - error verifying token: %s", err.Error())))
			if err != nil {
				log.Printf("error writing content: %s", err.Error())
				return
			}

			return
		}

		// third, if permissions are required for the route, check them
		if len(requiredPermissions) > 0 {
			isAllowed, err := a.CheckClaims(r.Context(), idToken, requiredPermissions...)
			if err != nil {
				log.Printf("error checking claims in secured route: %s", err.Error())

				w.Header().Add("content-type", "text/plain")
				w.WriteHeader(http.StatusUnauthorized)
				_, err := w.Write([]byte("forbidden"))
				if err != nil {
					log.Printf("error writing content: %s", err.Error())
					return
				}

				return
			}
			if !isAllowed {
				w.Header().Add("content-type", "text/plain")
				w.WriteHeader(http.StatusUnauthorized)
				_, err := w.Write([]byte("insufficient access rights"))
				if err != nil {
					log.Printf("error writing content: %s", err.Error())
					return
				}

				return
			}
		}

		// the call is fully authenticated and authorized, call the next handler
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
			_, err := w.Write([]byte("Failed to exchange an authorization code for a token."))
			if err != nil {
				log.Printf("error writing to response writer: %s", err.Error())
				return
			}

			return
		}

		if state != "1234567890" { // TODO:
			log.Printf("invalid state parameter. Expected %s but got %s", "todo", state)
			w.WriteHeader(http.StatusUnauthorized)
			_, err := w.Write([]byte("Failed to exchange an authorization code for a token."))
			if err != nil {
				log.Printf("error writing to response writer: %s", err.Error())
				return
			}

			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, err := w.Write([]byte("Failed to exchange an authorization code for a token."))
			if err != nil {
				log.Printf("error writing to response writer: %s", err.Error())
				return
			}

			return
		}

		token, err := a.oAuthConfig.Exchange(ctx, code)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, err := w.Write([]byte("failed to exchange an authorization code for a token."))
			if err != nil {
				log.Printf("error writing to response writer: %s", err.Error())
				return
			}

			return
		}

		idToken, err := a.VerifyIDToken(ctx, token)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte("failed to verify token."))
			if err != nil {
				log.Printf("error writing to response writer: %s", err.Error())
				return
			}

			return
		}

		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte(err.Error()))
			if err != nil {
				log.Printf("error writing to response writer: %s", err.Error())
				return
			}
			
			return
		}

		a.SessionManager.Put(r.Context(), "email", claims["email"])
		a.SessionManager.Put(r.Context(), "accessToken", token.AccessToken)

		// Redirect to logged in page.
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
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

func (a *Authenticator) GetClaimsFromToken(ctx context.Context, idToken *oidc.IDToken) (map[string]interface{}, error) {
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

	// build up a string slice containing all permissions from the token
	rawTokenPermissions := claims["permissions"].([]interface{})
	tokenPermissions := make([]string, len(rawTokenPermissions))
	for i, v := range rawTokenPermissions {
		tokenPermissions[i] = fmt.Sprint(v)
	}

	// only if all permissions are present the result is true
	for _, requiredPermission := range requiredPermissions {
		isPresent := contains(tokenPermissions, requiredPermission)
		if !isPresent {
			return false, nil
		}
	}

	return true, nil
}

// contains checks if the given token exists in the container
func contains[T comparable](container []T, token T) bool {
	for _, d := range container {
		if d == token {
			return true
		}
	}

	return false
}
