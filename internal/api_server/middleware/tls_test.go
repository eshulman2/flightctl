package middleware_test

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/flightctl/flightctl/internal/api_server/middleware"
	"github.com/flightctl/flightctl/internal/config"
	"github.com/flightctl/flightctl/internal/consts"
	"github.com/flightctl/flightctl/internal/crypto"
	testutil "github.com/flightctl/flightctl/test/util"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestTLSServer(t *testing.T, handshakeTimeout time.Duration) (string, *x509.Certificate, *crypto.TLSCertificateConfig, func()) {
	t.Helper()

	tempDir := t.TempDir()
	log := logrus.New()
	log.SetOutput(io.Discard)

	cfg := config.NewDefault()
	cfg.Service.CertStore = tempDir
	cfg.CA.InternalConfig.CertStore = tempDir

	ca, serverCerts, clientCert, err := testutil.NewTestCerts(cfg)
	require.NoError(t, err)

	_, tlsConfig, err := crypto.TLSConfigForServer(ca.GetCABundleX509(), serverCerts)
	require.NoError(t, err)

	listener, err := middleware.NewTLSListener("127.0.0.1:0", tlsConfig)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		peerCert := r.Context().Value(consts.TLSPeerCertificateCtxKey)
		if peerCert != nil {
			cert := peerCert.(*x509.Certificate)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(cert.Subject.CommonName))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})

	srv := middleware.NewHTTPServer(mux, log, listener.Addr().String(), cfg)
	srv.ConnContext = middleware.TLSClientCertConnContextWithTimeout(log, handshakeTimeout)

	serverErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			serverErr <- err
		}
	}()

	cleanup := func() {
		_ = srv.Close()
		_ = listener.Close()
	}

	return listener.Addr().String(), ca.GetCABundleX509()[0], clientCert, cleanup
}

func TestTLSClientCertConnContext(t *testing.T) {
	t.Run("When connection is not tls.Conn it should return context unchanged", func(t *testing.T) {
		log := logrus.New()
		log.SetOutput(io.Discard)
		connCtx := middleware.TLSClientCertConnContext(log)

		serverPipe, clientPipe := net.Pipe()
		defer serverPipe.Close()
		defer clientPipe.Close()

		ctx := context.Background()
		resCtx := connCtx(ctx, serverPipe)
		assert.Equal(t, ctx, resCtx)
		assert.Nil(t, resCtx.Value(consts.TLSPeerCertificateCtxKey))
	})

	t.Run("When timeout is zero or negative it should default to DefaultTLSHandshakeTimeout", func(t *testing.T) {
		assert.Equal(t, 10*time.Second, middleware.DefaultTLSHandshakeTimeout)
	})

	t.Run("When TLS handshake succeeds it should store peer certificate in request context", func(t *testing.T) {
		addr, caCert, clientCert, cleanup := setupTestTLSServer(t, 5*time.Second)
		defer cleanup()

		client, err := testutil.NewBareHTTPsClient([]*x509.Certificate{caCert}, clientCert)
		require.NoError(t, err)

		resp, err := client.Get("https://" + addr + "/test")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.NotEmpty(t, string(body))
	})

	t.Run("When TLS handshake stalls it should timeout, close connection, and allow subsequent connections", func(t *testing.T) {
		handshakeTimeout := 150 * time.Millisecond
		addr, caCert, clientCert, cleanup := setupTestTLSServer(t, handshakeTimeout)
		defer cleanup()

		// Stalled client: opens raw TCP connection but never sends TLS ClientHello
		stalledConn, err := net.DialTimeout("tcp", addr, time.Second)
		require.NoError(t, err)
		defer stalledConn.Close()

		// Verify stalled connection gets closed by the server after the handshake timeout
		readErrCh := make(chan error, 1)
		go func() {
			buf := make([]byte, 10)
			_ = stalledConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, readErr := stalledConn.Read(buf)
			readErrCh <- readErr
		}()

		select {
		case readErr := <-readErrCh:
			// Server should have closed the connection resulting in EOF or closed error
			require.Error(t, readErr)
			assert.True(t, errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) || errors.Is(readErr, io.ErrUnexpectedEOF),
				"expected EOF or connection closed error, got: %v", readErr)
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for server to close stalled TLS connection")
		}

		// Subsequent legitimate client must succeed without being blocked
		client, err := testutil.NewBareHTTPsClient([]*x509.Certificate{caCert}, clientCert)
		require.NoError(t, err)

		resp, err := client.Get("https://" + addr + "/test")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("When client stalls concurrently it should unblock listener so legitimate client succeeds", func(t *testing.T) {
		handshakeTimeout := 200 * time.Millisecond
		addr, caCert, clientCert, cleanup := setupTestTLSServer(t, handshakeTimeout)
		defer cleanup()

		// Start stalled client connection
		stalledConn, err := net.DialTimeout("tcp", addr, time.Second)
		require.NoError(t, err)
		defer stalledConn.Close()

		// Legitimate client connects concurrently while stalled client connection was initiated
		var wg sync.WaitGroup
		wg.Add(1)
		var legitimateErr error
		var statusCode int

		go func() {
			defer wg.Done()
			client, err := testutil.NewBareHTTPsClient([]*x509.Certificate{caCert}, clientCert)
			if err != nil {
				legitimateErr = err
				return
			}
			resp, err := client.Get("https://" + addr + "/test")
			if err != nil {
				legitimateErr = err
				return
			}
			defer resp.Body.Close()
			statusCode = resp.StatusCode
		}()

		wg.Wait()
		require.NoError(t, legitimateErr)
		assert.Equal(t, http.StatusOK, statusCode)
	})
}
