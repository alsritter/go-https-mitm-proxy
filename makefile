
test:
	https_proxy="http://localhost:6789" curl https://github.com

gen_root_cert:
	openssl genrsa -out rootCa.key 2048
	openssl req -new -key rootCa.key -out rootCa.csr
	openssl x509 -req -days 365 -in rootCa.csr -signkey rootCa.key -out rootCa.crt
