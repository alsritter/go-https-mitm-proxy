package proxy

import (
	"crypto/rsa"
	"crypto/x509"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/alsritter/https-proxy/gen_cert"
)

var rootCert *x509.Certificate
var rootKey *rsa.PrivateKey

func init() {
	var err error
	rootCert, rootKey, err = gen_cert.LoadRootCertificate("./rootCa.crt", "./rootCa.key")
	if err != nil {
		log.Fatal(err)
	}
}

type proxyServer struct {
	handler func(w http.ResponseWriter, r *http.Request)
}

func (h *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL.Path)
	h.handler(w, r)
}

// CreateFakeHttpsWebSite 根据域名生成一个伪造的https服务
func CreateFakeHttpsWebSite(domain string, successFun func()) {
	cert, key, _ := gen_cert.CreateFakeCertificateByDomain(rootCert, rootKey, domain)

	// 生成伪造的证书..
	if err := ioutil.WriteFile("server_cert.pem", cert, fs.ModePerm); err != nil {
		log.Fatal(err)
	}
	if err := ioutil.WriteFile("server_key.pem", key, fs.ModePerm); err != nil {
		log.Fatal(err)
	}

	var waitGroup sync.WaitGroup
	waitGroup.Add(1)

	// fakeServer
	go func() {
		l, err := net.Listen("tcp", ":9080")
		if err != nil {
			log.Fatal(err)
		}
		// Signal that server is open for business.
		waitGroup.Done()
		if e := http.ServeTLS(l, &proxyServer{
			handler: func(pW http.ResponseWriter, pR *http.Request) {
				_, _ = pW.Write([]byte(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GitHub</title>
</head>
<body>
  这是一个伪造的 GitHub 站点~
</body>
</html>
`))
			}}, "server_cert.pem", "server_key.pem"); e != nil {
			log.Fatal(e)
		}
	}()

	waitGroup.Wait()
	successFun()
}
