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

func helloRoute(session *scs.SessionManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error

		email := session.GetString(r.Context(), "email")

		w.Header().Add("content-type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(fmt.Sprintf("<h2>Hello %s</h2>", email)))
		if err != nil {
			log.Print(err)
			return
		}
	})
}

func homeRoute(session *scs.SessionManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error

		w.Header().Add("content-type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(`<h2>Welcome!</h2> <a href="/auth/login">Login</a> <a href="/test">Protected route</a>`))
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

	// register the home route returning nothing but text for non logged in users
	mux.Handle("/", sessionManager.LoadAndSave((homeRoute(sessionManager))))

	// register the route to auth and wrap the final route with the
	// authentication
	mux.Handle("/test", sessionManager.LoadAndSave(authenticator.Protect(helloRoute(sessionManager), "read:test")))

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
