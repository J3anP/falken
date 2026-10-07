package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

var tlsPorts = map[int]bool{
	443:  true, // HTTPS
	8443: true,
	465:  true, // SMTPS
	636:  true, // LDAPS
	989:  true, // FTPS
	990:  true, // FTP
	993:  true, // IMAPS
	995:  true, // POP3S
}

func GrabTLSInfo(ctx context.Context, target string, port int, timeoutMs int) string {
	address := fmt.Sprintf("%s:%d", target, port)
	timeout := time.Duration(timeoutMs)*time.Millisecond

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	rawConn, err := d.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return ""
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         target,
	})
	defer tlsConn.Close()

	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		return ""
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	cert := certs[0]

	cn := cert.Subject.CommonName
	if cn == "" {
		cn = "(sin CN)"
	}
	issuer := cert.Issuer.CommonName
	if issuer == "" {
		issuer = "(desconocido)"
	}

	return fmt.Sprintf("TLS cert: CN=%s | Issuer=%s | Expira=%s",
		cn, issuer, cert.NotAfter.Format("2006-01-01"))
}