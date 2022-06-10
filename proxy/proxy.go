package proxy

import (
	"crypto/tls"
	"github.com/alsritter/https-proxy/cert_server"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	//RoundTrip 传递发送的请求返回响应的结果
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	//把目标服务器的响应header复制
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

//复制响应头
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func Serve() {
	sv := &http.Server{
		Addr: ":6789",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				log.Println(r.URL.Hostname())
				// 开启伪造的 https 服务
				cert_server.CreateFakeHttpsWebSite(r.URL.Hostname(), func() {
					//设置超时防止大量超时导致服务器资源不大量占用
					srvSocket, err := net.DialTimeout("tcp", "127.0.0.1:9080", 10*time.Second)
					if err != nil {
						http.Error(w, err.Error(), http.StatusServiceUnavailable)
						return
					}

					w.WriteHeader(http.StatusOK)
					//类型转换
					hijacker, ok := w.(http.Hijacker)
					if !ok {
						http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
						return
					}

					//接管连接
					cltSocket, _, err := hijacker.Hijack()
					if err != nil {
						http.Error(w, err.Error(), http.StatusServiceUnavailable)
					}

					go transfer(srvSocket, cltSocket)
					go transfer(cltSocket, srvSocket)
				})
			} else {
				//直接 http 代理
				handleHTTP(w, r)
			}
		}),
		// 关闭 http2
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Println("简易 HTTPS 中间人代理启动成功，端口：", 6789)
	log.Fatal(sv.ListenAndServe())
}

//转发连接的数据
func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}
