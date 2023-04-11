package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/niksteff/go-reserv/internal/auth"
	"github.com/niksteff/go-reserv/internal/config"
)

func securedRoute(authenticator *auth.Authenticator, requiredClaims ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error

		accessToken := authenticator.SessionManager.GetString(r.Context(), "accessToken")
		if accessToken == "" {
			w.Header().Add("content-type", "text/plain")
			w.WriteHeader(http.StatusUnauthorized)
			_, err = w.Write([]byte("forbidden"))
			if err != nil {
				log.Printf("error writing content: %s", err.Error())
				return
			}

			return
		}

		idToken, err := authenticator.VerifyRawToken(r.Context(), accessToken)
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

		isAllowed, err := authenticator.CheckClaims(r.Context(), idToken, requiredClaims...)
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

		email := authenticator.SessionManager.GetString(r.Context(), "email")

		w.Header().Add("content-type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(fmt.Sprintf("Hello %s", email)))
		if err != nil {
			log.Print(err)
			return
		}
	})
}

func main() {
	// this is the overall config for the service
	config, err := config.Load()
	if err != nil {
		log.Panicf("fatal error loading config: %s", err.Error())
		return
	}

	log.Printf("config loaded: %+v", config) // TODO: should be a debug statement

	// create a mux and register test routes
	mux := http.NewServeMux()

	// configure our session manager
	sessionManager := scs.New()
	sessionManager.Lifetime = 5 * time.Minute

	// this authenticator protects all routes
	authenticator, err := auth.NewAuthenticator(config.Auth, sessionManager)
	if err != nil {
		log.Panicf("fatal error creating new authenticator: %s", err.Error())
		return
	}

	// register the route to auth and wrap the final route with the
	// authentication
	mux.Handle("/test", sessionManager.LoadAndSave(authenticator.IsAuthenticated(securedRoute(authenticator, "read:test"))))

	// register the authorization routes
	mux.Handle("/auth/callback", sessionManager.LoadAndSave(authenticator.Callback()))
	mux.Handle("/auth/login", sessionManager.LoadAndSave(authenticator.Login()))

	// create a server and listen to the registered routes
	s := http.Server{
		Addr: "localhost:3000",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // TODO: provide a proper ssl config
		},
		ReadTimeout: time.Second * 30, // TODO: choose proper values for mobile clients etc
		Handler:     mux,
	}

	err = s.ListenAndServe()
	if err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			// connection was closed
			log.Panicf("connection closed: %s", err)
			return
		}
		log.Panicf("fatal error listening and serving: %s", err)
		return
	}
}
