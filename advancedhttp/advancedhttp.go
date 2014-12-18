package advancedhttp

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type ResponseWriter struct {
	W               http.ResponseWriter
	RewriteLocation bool
	StripListenPath bool
	ListenPath      string
	Length          int64
	Status          int
}

func (trw *ResponseWriter) Header() http.Header {
	return trw.W.Header()
}

func (trw *ResponseWriter) WriteHeader(status int) {
	trw.Status = status
	if location := trw.W.Header().Get("Location"); trw.RewriteLocation && location != "" && !strings.HasPrefix(location, "http") {
		if trw.StripListenPath {
			trw.W.Header().Set("Location", trw.ListenPath+location[1:])
		}
	}
	trw.W.WriteHeader(status)
}

func (trw *ResponseWriter) Write(bytes []byte) (int, error) {
	n, err := trw.W.Write(bytes)
	trw.Length += int64(n)
	return n, err
}

func (trw *ResponseWriter) Log(r *http.Request, userId string) {
	remoteIp := r.RemoteAddr
	if strings.Contains(remoteIp, ":") {
		remoteIp = strings.Split(remoteIp, ":")[0]
	}
	if userId == "" {
		userId = "-"
	}
	fmt.Printf("%v - %v [%v] \"%v %v %v\" %v %v %v %v\n", remoteIp, userId, time.Now().UTC().String(), r.Method, r.URL.String(), r.Proto, trw.Status, trw.Length, r.Referer(), r.UserAgent())
}

//Copied from the stdlib for ReverseProxy
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

//Copied and modified from stdlib for ReverseProxy
func SingleHostReverseProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		req.Host = target.Host
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
	}
	return &httputil.ReverseProxy{Director: director}
}
