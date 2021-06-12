package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/pquerna/otp"
	"github.com/subspacecommunity/subspace/cmd/subspace/cli"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/securecookie"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
)

var (
	// securetoken
	securetoken *securecookie.SecureCookie

	// logger
	logger = log.New()

	// config
	config *Config

	// mailer
	mailer = NewMailer()

	// SAML
	samlSP *samlsp.Middleware

	// Error page HTML
	errorPageHTML = `<html><head><title>Error</title></head><body text="orangered" bgcolor="black"><h1>An error has occurred</h1></body></html>`

	// theme
	semanticTheme string

	// Totp
	tempTotpKey *otp.Key
)

func main() {
	cli.SetStartupConfig()

	// http port
	httpIP, httpPort, err := net.SplitHostPort(cli.StartupConfig.HttpAddr)
	if err != nil {
		logger.Fatalf("invalid --http-addr: %s", err.Error())
	}

	// Clean datadir path.
	cli.StartupConfig.DataDir = filepath.Clean(cli.StartupConfig.DataDir)

	// config
	config, err := NewConfig("config.json")
	if err != nil {
		logger.Fatal(err)
	}

	// TOTP
	err = config.GenerateTOTP()
	if err != nil {
		logger.Fatal(err)
	}

	// Secure token
	securetoken = securecookie.New([]byte(config.FindInfo().HashKey), []byte(config.FindInfo().BlockKey))

	// Configure SAML if metadata is present.
	if len(config.FindInfo().SAML.IDPMetadata) > 0 {
		if err := configureSAML(); err != nil {
			logger.Warnf("configuring SAML failed: %s", err)
		}
	}

	//
	// Routes
	//
	r := &httprouter.Router{}
	r.GET("/", Log(WebHandler(indexHandler, "index")))
	r.GET("/help", Log(WebHandler(helpHandler, "help")))
	r.GET("/configure", Log(WebHandler(configureHandler, "configure")))
	r.POST("/configure", Log(WebHandler(configureHandler, "configure")))

	// SAML
	r.GET("/sso", Log(ssoHandler))
	r.GET("/saml/metadata", Log(samlHandler))
	r.POST("/saml/metadata", Log(samlHandler))
	r.GET("/saml/acs", Log(samlHandler))
	r.POST("/saml/acs", Log(samlHandler))

	r.GET("/totp/image", Log(WebHandler(totpQRHandler, "totp/image")))
	r.GET("/signin", Log(WebHandler(signinHandler, "signin")))
	r.GET("/signout", Log(WebHandler(signoutHandler, "signout")))
	r.POST("/signin", Log(WebHandler(signinHandler, "signin")))
	r.GET("/forgot", Log(WebHandler(forgotHandler, "forgot")))
	r.POST("/forgot", Log(WebHandler(forgotHandler, "forgot")))

	r.GET("/settings", Log(WebHandler(settingsHandler, "settings")))
	r.POST("/settings", Log(WebHandler(settingsHandler, "settings")))

	r.GET("/user/edit/:user", Log(WebHandler(userEditHandler, "user/edit")))
	r.POST("/user/edit", Log(WebHandler(userEditHandler, "user/edit")))
	r.GET("/user/delete/:user", Log(WebHandler(userDeleteHandler, "user/delete")))
	r.POST("/user/delete", Log(WebHandler(userDeleteHandler, "user/delete")))

	r.GET("/profile/add", Log(WebHandler(profileAddHandler, "profile/add")))
	r.POST("/profile/add", Log(WebHandler(profileAddHandler, "profile/add")))
	r.GET("/profile/connect/:profile", Log(WebHandler(profileConnectHandler, "profile/connect")))
	r.GET("/profile/delete/:profile", Log(WebHandler(profileDeleteHandler, "profile/delete")))
	r.POST("/profile/delete", Log(WebHandler(profileDeleteHandler, "profile/delete")))
	r.GET("/profile/config/wireguard/:profile", Log(WebHandler(wireguardConfigHandler, "profile/config/wireguard")))
	r.GET("/profile/qrconfig/wireguard/:profile", Log(WebHandler(wireguardQRConfigHandler, "profile/qrconfig/wireguard")))
	r.GET("/static/*path", staticHandler)

	//
	// Server
	//

	httpTimeout := 10 * time.Minute
	maxHeaderBytes := 10 * (1024 * 1024)

	// Plain text web server for use behind a reverse proxy.
	if !cli.StartupConfig.LetsEncrypt {
		httpd := &http.Server{
			Handler:        r,
			Addr:           net.JoinHostPort(httpIP, httpPort),
			WriteTimeout:   httpTimeout,
			ReadTimeout:    httpTimeout,
			MaxHeaderBytes: maxHeaderBytes,
		}
		hostport := net.JoinHostPort(cli.StartupConfig.HttpHost, httpPort)
		if httpPort == "80" {
			hostport = cli.StartupConfig.HttpHost
		}
		logger.Infof("Subspace version: %s %s", cli.Version, &url.URL{
			Scheme: "http",
			Host:   hostport,
			Path:   "/",
		})
		logger.Fatal(httpd.ListenAndServe())
	}

	// Let's Encrypt TLS mode

	// autocert
	certmanager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(filepath.Join(cli.StartupConfig.DataDir, "letsencrypt")),
		HostPolicy: func(_ context.Context, host string) error {
			host = strings.TrimPrefix(host, "www.")
			if host == cli.StartupConfig.HttpHost {
				return nil
			}
			if host == config.FindInfo().Domain {
				return nil
			}
			return fmt.Errorf("autocert: host %q not permitted by HostPolicy", host)
		},
	}

	// http redirect to https and Let's Encrypt auth
	go func() {
		redir := httprouter.New()
		redir.GET("/*path", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			r.URL.Scheme = "https"
			r.URL.Host = cli.StartupConfig.HttpHost
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
		})

		httpd := &http.Server{
			Handler:        certmanager.HTTPHandler(redir),
			Addr:           net.JoinHostPort(httpIP, "80"),
			WriteTimeout:   httpTimeout,
			ReadTimeout:    httpTimeout,
			MaxHeaderBytes: maxHeaderBytes,
		}
		if err := httpd.ListenAndServe(); err != nil {
			logger.Fatalf("http server on port 80 failed: %s", err)
		}
	}()

	// TLS
	tlsConfig := tls.Config{
		GetCertificate:           certmanager.GetCertificate,
		NextProtos:               []string{"http/1.1"},
		Rand:                     rand.Reader,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,

			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Override default for TLS.
	if httpPort == "80" {
		httpPort = "443"
		cli.StartupConfig.HttpAddr = net.JoinHostPort(httpIP, httpPort)
	}

	httpsd := &http.Server{
		Handler:        r,
		Addr:           cli.StartupConfig.HttpAddr,
		WriteTimeout:   httpTimeout,
		ReadTimeout:    httpTimeout,
		MaxHeaderBytes: maxHeaderBytes,
	}

	// Enable TCP keep alives on the TLS connection.
	tcpListener, err := net.Listen("tcp", cli.StartupConfig.HttpAddr)
	if err != nil {
		logger.Fatalf("listen failed: %s", err)
		return
	}
	tlsListener := tls.NewListener(tcpKeepAliveListener{tcpListener.(*net.TCPListener)}, &tlsConfig)

	hostport := net.JoinHostPort(cli.StartupConfig.HttpHost, httpPort)
	if httpPort == "443" {
		hostport = cli.StartupConfig.HttpHost
	}
	logger.Infof("Subspace version: %s %s", cli.Version, &url.URL{
		Scheme: "https",
		Host:   hostport,
		Path:   "/",
	})
	logger.Fatal(httpsd.Serve(tlsListener))
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (l tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := l.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(10 * time.Minute)
	return tc, nil
}

func configureSAML() error {
	info := config.FindInfo()

	if len(info.SAML.IDPMetadata) == 0 {
		return fmt.Errorf("no IDP metadata")
	}
	entity := &saml.EntityDescriptor{}
	err := xml.Unmarshal([]byte(info.SAML.IDPMetadata), entity)

	if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal([]byte(info.SAML.IDPMetadata), entities); err != nil {
			return err
		}

		err = fmt.Errorf("no entity found with IDPSSODescriptor")
		for i, e := range entities.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				entity = &entities.EntityDescriptors[i]
				err = nil
			}
		}
	}
	if err != nil {
		return err
	}

	keyPair, err := tls.X509KeyPair(info.SAML.Certificate, info.SAML.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to load SAML keypair: %s", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse SAML certificate: %s", err)
	}

	rootURL := url.URL{
		Scheme: "https",
		Host:   cli.StartupConfig.HttpHost,
		Path:   "/",
	}

	if cli.StartupConfig.HttpInsecure {
		rootURL.Scheme = "http"
	}

	newsp, err := samlsp.New(samlsp.Options{
		URL:               rootURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		IDPMetadata:       entity,
		CookieName:        SessionCookieNameSSO,
		CookieDomain:      cli.StartupConfig.HttpHost, // TODO: this will break if using a custom domain.
		CookieSecure:      !cli.StartupConfig.HttpInsecure,
		Logger:            logger,
		AllowIDPInitiated: true,
	})
	if err != nil {
		logger.Warnf("failed to configure SAML: %s", err)
		samlSP = nil
		return fmt.Errorf("failed to configure SAML: %s", err)
	}

	newsp.ServiceProvider.AuthnNameIDFormat = saml.EmailAddressNameIDFormat

	samlSP = newsp
	logger.Infof("successfully configured SAML")
	return nil
}
