package testutil

import (
	"flag"

	"github.com/higebu/go-niftycloud/niftycloud"
	. "gopkg.in/check.v1"
)

// Nifty must be used by all tested packages to determine whether to
// run functional tests against the real NIFTY Cloud servers.
var Nifty bool

func init() {
	flag.BoolVar(&Nifty, "nifty", false, "Enable tests against nifty server")
}

type LiveSuite struct {
	auth niftycloud.Auth
}

func (s *LiveSuite) SetUpSuite(c *C) {
	if !Nifty {
		c.Skip("nifty tests not enabled (-nifty flag)")
	}
	auth, err := niftycloud.EnvAuth()
	if err != nil {
		c.Fatal(err.Error())
	}
	s.auth = auth
}
