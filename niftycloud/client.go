package niftycloud

import (
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

type Env struct {
	MaxRetry          int
	ConnectionTimeout time.Duration
	SocketTimeout     time.Duration
}

var env = &Env{
	MaxRetry:          3,
	ConnectionTimeout: time.Duration(10) * time.Second,
	SocketTimeout:     30,
}

type RetryableFunc func(*http.Request, *http.Response, error) bool
type WaitFunc func(try int)
type DeadlineFunc func() time.Time

type ResilientTransport struct {
	// Timeout is the maximum amount of time a dial will wait for
	// a connect to complete.
	//
	// The default is no timeout.
	//
	// With or without a timeout, the operating system may impose
	// its own earlier timeout. For instance, TCP timeouts are
	// often around 3 minutes.
	DialTimeout time.Duration

	// MaxTries, if non-zero, specifies the number of times we will retry on
	// failure. Retries are only attempted for temporary network errors or known
	// safe failures.
	MaxTries    int
	Deadline    DeadlineFunc
	ShouldRetry RetryableFunc
	Wait        WaitFunc
	transport   *http.Transport
}

// Convenience method for creating an http client
func NewClient(rt *ResilientTransport, env *Env) *http.Client {
	m := os.Getenv("NIFTY_CLOUD_MAX_RETRY")
	if m != "" {
		env.MaxRetry, _ = strconv.Atoi(m)
	}
	c := os.Getenv("NIFTY_CLOUD_CONNECTION_TIMEOUT")
	if c != "" {
		i, _ := strconv.Atoi(c)
		env.ConnectionTimeout = time.Duration(i) * time.Second
	}
	s := os.Getenv("NIFTY_CLOUD_SOCKET_TIMEOUT")
	if s != "" {
		i, _ := strconv.Atoi(s)
		env.SocketTimeout = time.Duration(i) * time.Second
	}

	rt.transport = &http.Transport{
		Dial: func(netw, addr string) (net.Conn, error) {
			c, err := net.DialTimeout(netw, addr, env.ConnectionTimeout)
			if err != nil {
				return nil, err
			}
			c.SetDeadline(rt.Deadline())
			return c, nil
		},
		DisableKeepAlives: true,
		Proxy:             http.ProxyFromEnvironment,
	}
	// TODO: Would be nice is ResilientTransport allowed clients to initialize
	// with http.Transport attributes.
	return &http.Client{
		Transport: rt,
	}
}

var retryingTransport = &ResilientTransport{
	Deadline: func() time.Time {
		return time.Now().Add(env.SocketTimeout * time.Second)
	},
	DialTimeout: env.ConnectionTimeout,
	MaxTries:    env.MaxRetry,
	ShouldRetry: niftycloudRetry,
	Wait:        ExpBackoff,
}

// Exported default client
var RetryingClient = NewClient(retryingTransport, env)

func (t *ResilientTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.tries(req)
}

// Retry a request a maximum of t.MaxTries times.
// We'll only retry if the proper criteria are met.
// If a wait function is specified, wait that amount of time
// In between requests.
func (t *ResilientTransport) tries(req *http.Request) (res *http.Response, err error) {
	for try := 0; try < t.MaxTries; try += 1 {
		res, err = t.transport.RoundTrip(req)

		if !t.ShouldRetry(req, res, err) {
			break
		}
		if res != nil {
			res.Body.Close()
		}
		if t.Wait != nil {
			t.Wait(try)
		}
	}

	return
}

func ExpBackoff(try int) {
	time.Sleep(100 * time.Millisecond *
		time.Duration(math.Exp2(float64(try))))
}

func LinearBackoff(try int) {
	time.Sleep(time.Duration(try*100) * time.Millisecond)
}

// Decide if we should retry a request.
func niftycloudRetry(req *http.Request, res *http.Response, err error) bool {
	retry := false

	// Retry if there's a temporary network error.
	if neterr, ok := err.(net.Error); ok {
		if neterr.Temporary() {
			retry = true
		}
	}

	// Retry if we get a 5xx series error.
	if res != nil {
		if res.StatusCode >= 500 && res.StatusCode < 600 {
			retry = true
		}
	}

	return retry
}
