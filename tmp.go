//go:build !linux
// +build !linux

package main

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func (c *http2Client) handleTunneling(w http.ResponseWriter, r *http.Request) {
	conn := network.ConnFromHijack(w)
	if conn == nil {
		return
	}
	defer conn.Close()

	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	req := &http.Request{
		Header: make(http.Header),
		Method: strings.ToUpper(c.config.Method),
		Host:   host,
		URL: &url.URL{
			Scheme: "https",
			Host:   c.config.ServerAddr,
			Path:   c.config.Url,
		},
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Body:          pr,
		ContentLength: -1,
	}
	if c.config.User != "" && c.config.Pwd != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.config.User+":"+c.config.Pwd)))
	}

	resp, err := h2c.c.Do(req)
	if err != nil {
		log.DefaultLogger.Errorf("error connect proxy server request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.DefaultLogger.Errorf("proxy server resp status:%d,proto:%s", resp.StatusCode, resp.Proto)
		return
	} else {
		log.DefaultLogger.Debugf("proxy server resp status:%d,proto:%s", resp.StatusCode, resp.Proto)
	}

	errCh := make(chan error, 2)
	h2c.add(1)
	if r.Method == http.MethodConnect {
		go network.Proxy(pw, conn, errCh)
	} else {
		log.DefaultLogger.Infof("%s method proxy", r.Method)
		go writePw(r, errCh, pw)
	}

	go network.Proxy(conn, resp.Body, errCh)
	err = <-errCh
	log.DefaultLogger.Infof("client %d pipe err:%v", h2c.i, err)
	h2c.add(-1)
}

func Proxy(dst io.Writer, src io.Reader, errCh chan error) {
	buf := lPool.Get().([]byte)
	defer lPool.Put(buf)

	n, err := io.CopyBuffer(dst, src, buf)
	log.DefaultLogger.Infof("pipe n:%d,err:%v", n, err)
	errCh <- err
}

func ConnFromHijack(w http.ResponseWriter) net.Conn {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}
	return conn
}
