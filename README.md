本文的完整代码放在了我的 GitHub 仓库 [go-https-mitm-proxy](https://github.com/alsritter/go-https-mitm-proxy)

## HTTP 的代理
HTTP 代理分为两种：

**普通代理**：这种代理也就是扮演着 “中间人” 的角色。对于用户的客户端来说，代理是服务端；对于远程的服务端来说，代理是客户端。代理也就是将用户的请求做了转发，真正请求服务器的是代理。服务器从而也就无法知道用户客户端的真实 IP 了。

![](https://image.alsritter.icu/img20220608203543.png)

**隧道代理**：这种代理能够以 HTTP 的方式实现任意基于 TCP 的应用层协议代理。你可以使用它来实现任何基于 TCP 协议的代理，典型的就像 WebSocket 这种。它是先通过 HTTP 的 CONNECT 方法请求服务端，然后在客户端与服务端间建立起一条 TCP 连接，之后对客户端与服务器之间的代理进行无脑转发（盲转发）。

![](https://image.alsritter.icu/img20220608203650.png)

之所以 HTTPS 使用这种隧道就是为了避免中间人攻击

## https 请求拦截
https 的请求相对于 http 的请求流程稍微复杂一点，目前的浏览器主要采用 tls1.2 版本和 tls1.3 版本，在开发 https 的代理之前，先看一下 https 采用 tls1.2 的握手过程是怎么样的

其过程可以通过 wireshark 抓包进行分析，通过 `tls and ip.addr=[目录ip]` 对 https 通信过程中的数据进行过滤

![](https://image.alsritter.icu/img20220608213826.png)

对应的图解如下所示：

![](https://image.alsritter.icu/img20220608212750.png)

CA 保证了通信双方的身份的真实性，基于公私钥交换确保了通信过程中的安全性

## 方案设计
那么想要对 https 请求进行代理应该如何实现呢？有两种办法可以对 https 的请求进行代理：

1、获取到所要代理网站 https 证书颁发机构的私钥，也就是 CA 根证书的私钥，然后自己再重新颁发一个新的证书返回给被代理的客户端
2、自己生成一个 CA 证书，然后导入到将要被代理的客户端中，让其信任，随后再针对将要代理的请求动态生成 https 证书

第一种方式很明显不合适，所以使用方案二，流程如下：

![](https://image.alsritter.icu/img20220608215029.png)

:::tip
fidder 就是通过客户端信任自建根证书来代理请求的
:::


由上知识点，我们可以这样设计

首先通过一个普通的代理

```sh
export https_proxy="http://localhost:6789"
```

把 https 请求代理到本地程序中（这里的 6789 端口），因为本地程序拿到这个 https 请求的 Method 是 CONNECT，所以需要再开启一个伪造的服务

第一层的代理（6789 端口）把请求转发到这个伪造的服务中，因为这个伪造的服务使用了上面信任的自签根证书去签发伪造的证书，所以目标请求就会认为当前伪造的服务就是真实的服务地址，因此就能顺利的 Mock 到对应的 https 请求了

## 生成根证书
具体参考 openssl 生成 CA 证书那篇笔记，这里就不再过多阐述，直接贴命令

生成CA私钥（.key）–> 生成CA证书请求（.csr）–> 自签名得到根证书（.crt）CA 给自已颁发的证书。

```sh
# Generate CA private key (制作ca.key 私钥)
openssl genrsa -out rootCa.key 2048

# Generate CSR 
openssl req -new -key rootCa.key -out rootCa.csr

# Generate Self Signed certificate（CA 根证书）
openssl x509 -req -days 365 -in rootCa.csr -signkey rootCa.key -out rootCa.crt
```

整个提示将如下所示：

```
OutputCountry Name (2 letter code) [AU]:CN
State or Province Name (full name) [Some-State]:Guangdong
Locality Name (eg, city) []:Shenzhen
Organization Name (eg, company) [Internet Widgits Pty Ltd]:alsritter, Inc.
Organizational Unit Name (eg, section) []:R&D Department
Common Name (e.g. server FQDN or YOUR name) []:alsritter CA ROOT
Email Address []:alsritter@outlook.com
```

证书内容检查工具 [证书查看](https://myssl.com/cert_decode.html) 

然后需要让你的操作系统信任该证书。

Ubuntu 下添加系统根证书, 只要将证书(扩展名为 crt)复制到 `/usr/local/share/ca-certificates` 文件夹然后运行 `update-ca-certificates` 即可。

```sh
$ sudo cp 证书路径.crt /usr/local/share/ca-certificates
$ sudo update-ca-certificates
```

删除证书：

```sh
$ sudo rm -f /usr/local/share/ca-certificates/证书.crt
$ sudo update-ca-certificates
```

:::tip
OS X 系统可以用 Keychain Access 来处理，参见 [Getting OS X to trust self-signed SSL certificates](https://tosbourn.com/getting-os-x-to-trust-self-signed-ssl-certificates)

Windows 系统直接安装信任就行了
:::

## 通过根证书签发伪造证书
有了根证书之后，就可以通过这个证书去伪造签发各种域名的请求了

首先是加载根证书

```go
// 加载证书与秘钥
// @param rootCa 证书文件
// @param rootKey 秘钥
func LoadRootCertificate(rootCa, rootKey string) (*x509.Certificate, *rsa.PrivateKey, error) {
	/**  首先读取根证书的证书和私钥  **/
	//解析根证书
	caFile, err := ioutil.ReadFile(rootCa)
	if err != nil {
		return nil, nil, err
	}

	caBlock, _ := pem.Decode(caFile)
	rootCert, err := x509.ParseCertificate(caBlock.Bytes)

	if err != nil {
		return nil, nil, err
	}

	//解析私钥
	keyFile, err := ioutil.ReadFile(rootKey)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyFile)
	praKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return rootCert, praKey, nil
}
```

然后创建一个证书模板文件，之后就可以根据这个模板生成证书了，值得注意是，这里唯一入参是 domain，就是需要伪造证书的那个域名

```go
func generateCertTemplate(domain string) *x509.Certificate {
	/**  然后需要生成新证书的模板,里面的字段根据自己需求填写  **/
	rd := random.New(random.NewSource(time.Now().UnixNano()))
	cer := &x509.Certificate{
		SerialNumber: big.NewInt(rd.Int63()), //证书序列号
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"https-mitm-proxy"},
			OrganizationalUnit: []string{"https-mitm-proxy"},
			Province:           []string{"ShenZhen"},
			CommonName:         domain,
			Locality:           []string{"ShenZhen"},
		},
		NotBefore:             time.Now(),                                                                 //证书有效期开始时间
		NotAfter:              time.Now().AddDate(1, 0, 0),                                                //证书有效期结束时间
		BasicConstraintsValid: true,                                                                       //基本的有效性约束
		IsCA:                  false,                                                                      //是否是根证书
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, //证书用途(客户端认证，数据加密)
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
	}
	return cer
}
```

最后根据上面两个提供的数据去生成一个伪造的证书

```go
// CreateFakeCertificateByDomain 根据所给域名生成对应证书
func CreateFakeCertificateByDomain(rootCert *x509.Certificate, rootKey *rsa.PrivateKey, domain string) ([]byte, []byte, error) {
	templateCert := generateCertTemplate(domain)
	//生成公钥私钥对
	priKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.CreateCertificate(rand.Reader, templateCert, rootCert, &priKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}

	//编码证书文件和私钥文件
	caPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca,
	}
	ca = pem.EncodeToMemory(caPem)
	buf := x509.MarshalPKCS1PrivateKey(priKey)
	keyPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: buf,
	}
	key := pem.EncodeToMemory(keyPem)

	return ca, key, nil
}
```

## 根据域名去伪造 HTTPS 服务
有了上面的自签证书，现在就可以根据这个自签的证书去启动一个伪造的服务站点

```go
package proxy

import (
	"crypto/rsa"
	"crypto/x509"
	"github.com/alsritter/https-proxy/gen_cert"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"
)

var rootCert *x509.Certificate
var rootKey *rsa.PrivateKey

func init() {
	var err error
	rootCert, rootKey, err = gen_cert.LoadRootCertificate("./ca.crt", "./ca.key")
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
```


## 编写转发代理
最后就是把所有的请求转发到这么伪造的服务端了，之前说了，这层代理只能使用通道去连接，所以只能使用 tcp 去连接

```go
import (
	"crypto/tls"
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
				CreateFakeHttpsWebSite(r.URL.Hostname(), func() {
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
```

## 使用测试

这里使用环境变量去让 curl 的请求转发到 localhost:6789 里面

```sh
# 注意 proxy 是 http 不是 https
$ https_proxy="http://localhost:6789" curl https://github.com
```

打印结果：

![20220610151349](https://image.alsritter.icu/images/20220610151349.png)


## 注意点

证书太弱，如下所示：

```sh
$ https_proxy="http://localhost:6789" curl https://github.com -I

HTTP/1.1 200 Connection Established
Proxy-agent: MITM-proxy

curl: (60) SSL certificate problem: CA certificate key too weak
More details here: https://curl.haxx.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

解决方法：

方式一：修改秘钥长度

生成秘钥时命令如下

```sh
openssl genrsa -des3 -out server.key 1024
```

改为

```sh
openssl genrsa -des3 -out server.key 2048
```

方式二，使用 `--ciphers` flag 修改 ssl 证书的验证等级

```sh
$ https_proxy="http://localhost:6789" curl https://github.com --ciphers DEFAULT@SECLEVEL=1
```


## References
* [SSL certificate: EE certificate key too weak](https://superuser.com/questions/1640089/ssl-certificate-ee-certificate-key-too-weak)
* [https-mitm-proxy-handbook](https://github.com/wuchangming/https-mitm-proxy-handbook)
* [java实现http/https抓包拦截](https://blog.csdn.net/puhaiyang/article/details/102649498)
* [关于我用 Go 写 HTTP(S) 代理这档事](https://github.red/http-proxy-with-go/)