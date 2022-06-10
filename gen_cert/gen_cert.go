package gen_cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	random "math/rand"
	"time"
)

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
