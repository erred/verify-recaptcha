package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	Debug   = false
	Origins = make(map[string]struct{})
	Port    = os.Getenv("PORT")

	// service stuff
	ServerKey       = strings.TrimSpace(os.Getenv("RECAPTCHA_KEY"))
	VerifyURL       = "https://www.google.com/recaptcha/api/siteverify"
	JSONContentType = "application/json"
)

func init() {
	// grpc stuff
	if os.Getenv("DEBUG") == "1" {
		Debug = true
	}

	for _, o := range strings.Split(os.Getenv("ORIGINS"), ",") {
		Origins[strings.TrimSpace(o)] = struct{}{}
	}

	if Port == "" {
		Port = ":8080"
	}
	if Port[0] != ':' {
		Port = ":" + Port
	}
}

func main() {
	http.ListenAndServe(Port, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := r.Header.Get("origin")
		if _, ok := Origins[o]; ok {
			w.Header().Set("access-control-allow-origin", o)
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("access-control-allow-methods", "POST, GET, OPTIONS")
			w.WriteHeader(http.StatusOK)
			return
		}

		defer r.Body.Close()
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("ReadAll request body: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		o = r.Header.Get("x-forwarded-for")

		v := url.Values{}
		v.Set("secret", ServerKey)
		v.Set("response", string(b))
		v.Set("remoteip", o)

		res, err := http.PostForm(VerifyURL, v)
		if err != nil {
			log.Printf("verify POST: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()
		b, err = ioutil.ReadAll(res.Body)
		if err != nil {
			log.Printf("ReadAll response body: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		rec := RecaptchaRes{}
		if err := json.Unmarshal(b, &rec); err != nil {
			log.Printf("json Unmarshal: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if Debug {
			log.Printf("parsed rec %v from %v\n", rec, string(b))
		}

		log.Printf("Verified from %v response %v\n", o, rec)
		if !rec.Success {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

type RecaptchaReq struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
	RemoteIP string `json:"remoteip"`
}
type RecaptchaRes struct {
	Success    bool      `json:"success"`
	Score      float64   `json:"score"`
	Action     string    `json:"action"`
	Timestamp  time.Time `json:"challenge_ts"`
	Hostname   string    `json:"hostname"`
	ErrorCodes []string  `json:"error-codes"`
}
