package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http2"
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
				CreateFakeHttpsWebSite(r.URL.Hostname(), func() {
					// //设置超时防止大量超时导致服务器资源不大量占用
					// srvSocket, err := net.DialTimeout("tcp", "127.0.0.1:9080", 10*time.Second)
					// if err != nil {
					// 	http.Error(w, err.Error(), http.StatusServiceUnavailable)
					// 	return
					// }

					conn := ConnFromHijack(w)
					if conn == nil {
						return
					}
					defer conn.Close()

					pr, pw := io.Pipe()
					defer pr.Close()
					defer pw.Close()

					req := &http.Request{
						Header: make(http.Header),
						Method: strings.ToUpper(http.MethodPost),
						Host:   r.URL.Hostname(),
						URL: &url.URL{
							Scheme: "https",
							Host:   "127.0.0.1:9080",
							Path:   r.URL.Path,
						},
						Proto:         "HTTP/2.0",
						ProtoMajor:    2,
						ProtoMinor:    0,
						Body:          pr,
						ContentLength: -1,
					}

					client := http.Client{
						Transport: &http2.Transport{
							TLSClientConfig: &tls.Config{
								InsecureSkipVerify: true,
							},
						},
					}

					resp, err := client.Do(req)
					if err != nil {
						fmt.Printf("error connect proxy server request: %v", err)
						return
					}

					defer resp.Body.Close()

					if resp.StatusCode != 200 {
						fmt.Printf("proxy server resp status:%d,proto:%s", resp.StatusCode, resp.Proto)
						return
					} else {
						fmt.Printf("proxy server resp status:%d,proto:%s", resp.StatusCode, resp.Proto)
					}

					go transfer(pw, conn)
					go transfer(conn, resp.Body)

					// w.WriteHeader(http.StatusOK)
					// //类型转换
					// hijacker, ok := w.(http.Hijacker)
					// if !ok {
					// 	http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
					// 	return
					// }

					// //接管连接
					// cltSocket, _, err := hijacker.Hijack()
					// if err != nil {
					// 	http.Error(w, err.Error(), http.StatusServiceUnavailable)
					// }

					// go transfer(srvSocket, cltSocket)
					// go transfer(cltSocket, srvSocket)
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

func ConnFromHijack(w http.ResponseWriter) net.Conn {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}
	return conn
}
