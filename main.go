package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	Origins = make(map[string]struct{})
	Port    = os.Getenv("PORT")

	// service stuff
	ServerKey       = strings.TrimSpace(os.Getenv("RECAPTCHA_KEY"))
	VerifyURL       = "https://www.google.com/recaptcha/api/siteverify"
	JSONContentType = "application/json"
)

func initLog() {
	logfmt := os.Getenv("LOGFMT")
	if logfmt != "json" {
		logfmt = "text"
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, NoColor: !terminal.IsTerminal(int(os.Stdout.Fd()))})
	}

	level, _ := zerolog.ParseLevel(os.Getenv("LOGLVL"))
	if level == zerolog.NoLevel {
		level = zerolog.InfoLevel
	}
	log.Info().Str("FMT", logfmt).Str("LVL", level.String()).Msg("log initialized")
	zerolog.SetGlobalLevel(level)
}

func main() {
	initLog()

	var ors []string
	for _, o := range strings.Split(os.Getenv("ORIGINS"), ",") {
		ors = append(ors, strings.TrimSpace(o))
		Origins[strings.TrimSpace(o)] = struct{}{}
	}

	if Port == "" {
		Port = ":8080"
	}
	if Port[0] != ':' {
		Port = ":" + Port
	}

	log.Info().Str("port", Port).Strs("origins", ors).Msg("serving")
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
			log.Error().Err(err).Msg("read request body")
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
			log.Error().Err(err).Msg("verify POST")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()
		b, err = ioutil.ReadAll(res.Body)
		if err != nil {
			log.Error().Err(err).Msg("read response body")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		rec := RecaptchaRes{}
		if err := json.Unmarshal(b, &rec); err != nil {
			log.Error().Err(err).Msg("unmarshal json")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// if Debug {
		// 	log.Printf("parsed rec %v from %v\n", rec, string(b))
		// }

		log.Info().Str("origin", o).Bool("success", rec.Success).Float64("score", rec.Score).Str("action", rec.Action).Time("ts", rec.Timestamp).Str("host", rec.Hostname).Strs("errcodes", rec.ErrorCodes).Msg("verified")
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
