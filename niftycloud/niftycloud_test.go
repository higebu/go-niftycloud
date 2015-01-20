package niftycloud_test

import (
	"os"
	"strings"
	"testing"

	"github.com/higebu/go-niftycloud/niftycloud"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

var _ = Suite(&S{})

type S struct {
	environ []string
}

func (s *S) SetUpSuite(c *C) {
	s.environ = os.Environ()
}

func (s *S) TearDownTest(c *C) {
	os.Clearenv()
	for _, kv := range s.environ {
		l := strings.SplitN(kv, "=", 2)
		os.Setenv(l[0], l[1])
	}
}

func (s *S) TestEnvAuthNoSecret(c *C) {
	os.Clearenv()
	_, err := niftycloud.EnvAuth()
	c.Assert(err, ErrorMatches, "NIFTY_CLOUD_SECRET_ACCESS_KEY or NIFTY_CLOUD_SECRET_KEY not found in environment")
}

func (s *S) TestEnvAuthNoAccess(c *C) {
	os.Clearenv()
	os.Setenv("NIFTY_CLOUD_SECRET_ACCESS_KEY", "foo")
	_, err := niftycloud.EnvAuth()
	c.Assert(err, ErrorMatches, "NIFTY_CLOUD_ACCESS_KEY_ID or NIFTY_CLOUD_ACCESS_KEY not found in environment")
}

func (s *S) TestEnvAuth(c *C) {
	os.Clearenv()
	os.Setenv("NIFTY_CLOUD_SECRET_ACCESS_KEY", "secret")
	os.Setenv("NIFTY_CLOUD_ACCESS_KEY_ID", "access")
	auth, err := niftycloud.EnvAuth()
	c.Assert(err, IsNil)
	c.Assert(auth, Equals, niftycloud.Auth{SecretKey: "secret", AccessKey: "access"})
}

func (s *S) TestEnvAuthAlt(c *C) {
	os.Clearenv()
	os.Setenv("NIFTY_CLOUD_SECRET_KEY", "secret")
	os.Setenv("NIFTY_CLOUD_ACCESS_KEY", "access")
	auth, err := niftycloud.EnvAuth()
	c.Assert(err, IsNil)
	c.Assert(auth, Equals, niftycloud.Auth{SecretKey: "secret", AccessKey: "access"})
}

func (s *S) TestGetAuthStatic(c *C) {
	auth, err := niftycloud.GetAuth("access", "secret")
	c.Assert(err, IsNil)
	c.Assert(auth, Equals, niftycloud.Auth{SecretKey: "secret", AccessKey: "access"})
}

func (s *S) TestGetAuthEnv(c *C) {
	os.Clearenv()
	os.Setenv("NIFTY_CLOUD_SECRET_ACCESS_KEY", "secret")
	os.Setenv("NIFTY_CLOUD_ACCESS_KEY_ID", "access")
	auth, err := niftycloud.GetAuth("", "")
	c.Assert(err, IsNil)
	c.Assert(auth, Equals, niftycloud.Auth{SecretKey: "secret", AccessKey: "access"})
}

func (s *S) TestEncode(c *C) {
	c.Assert(niftycloud.Encode("foo"), Equals, "foo")
	c.Assert(niftycloud.Encode("/"), Equals, "%2F")
}

func (s *S) TestRegionsAreNamed(c *C) {
	for n, r := range niftycloud.Regions {
		c.Assert(n, Equals, r.Name)
	}
}
