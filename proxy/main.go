package main

import (
	"log"
	"net/http"
)

const port = ":6789"

type httpMitmProxy struct{}

func (s *httpMitmProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf(`
				protocol: %s,
        hostname: %s,
        method: %s,
        port: %s,
        path: %s,
        headers: %+v
	`,
		r.Proto,
		r.URL.Hostname(),
		r.Method,
		r.URL.Port(),
		r.URL.Path,
		r.Header,
	)

	w.Write([]byte("Hello, This is Proxy Server ~"))
}

func main() {
	server := &httpMitmProxy{}
	log.Println("HTTP 中间人代理启动成功, 端口：", port)
	http.ListenAndServe(port, server)
}
