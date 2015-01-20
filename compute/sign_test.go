package compute_test

import (
	"github.com/higebu/go-niftycloud/compute"
	"github.com/higebu/go-niftycloud/niftycloud"
	. "gopkg.in/check.v1"
)

// NIFTY Cloud Compute ReST authentication docs: http://cloud.nifty.com/api/rest/authenticate.htm

var testAuth = niftycloud.Auth{AccessKey: "user", SecretKey: "secret"}

func (s *S) TestBasicSignature(c *C) {
	params := map[string]string{}
	compute.Sign(testAuth, "GET", "/path", params, "localhost")
	c.Assert(params["SignatureVersion"], Equals, "2")
	c.Assert(params["SignatureMethod"], Equals, "HmacSHA256")
	expected := "dyt4KTzu1bCyj2YXl085hkfuFdM2l8EdQtxh5Q6SmMw="
	c.Assert(params["Signature"], Equals, expected)
}

func (s *S) TestParamSignature(c *C) {
	params := map[string]string{
		"param1": "value1",
		"param2": "value2",
		"param3": "value3",
	}
	compute.Sign(testAuth, "GET", "/path", params, "localhost")
	expected := "tlrQX3I07ZDfnIfxeV3Qsn1iwJod9tLc4IJakOz7gqw="
	c.Assert(params["Signature"], Equals, expected)
}

func (s *S) TestManyParams(c *C) {
	params := map[string]string{
		"param1":  "value10",
		"param2":  "value2",
		"param3":  "value3",
		"param4":  "value4",
		"param5":  "value5",
		"param6":  "value6",
		"param7":  "value7",
		"param8":  "value8",
		"param9":  "value9",
		"param10": "value1",
	}
	compute.Sign(testAuth, "GET", "/path", params, "localhost")
	expected := "WDWtj0KhB2Eo5nFhtIP/IgzLWxTtybj9pl5ZXDjKg3g="
	c.Assert(params["Signature"], Equals, expected)
}

func (s *S) TestEscaping(c *C) {
	params := map[string]string{"Nonce": "+ +"}
	compute.Sign(testAuth, "GET", "/path", params, "localhost")
	c.Assert(params["Nonce"], Equals, "+ +")
	expected := "Z9OD4EuFPrQHc3byR0SMDsJ+oFdsysIIBHMG6mjs7qk="
	c.Assert(params["Signature"], Equals, expected)
}

func (s *S) TestSignatureExample1(c *C) {
	params := map[string]string{
		"Timestamp": "2009-02-01T12:53:20+00:00",
		"Version":   "2007-11-07",
		"Action":    "ListDomains",
	}
	compute.Sign(niftycloud.Auth{AccessKey: "access", SecretKey: "secret"}, "GET", "/", params, "sdb.nifty.com")
	expected := "i/oJBLCLE8wMI0zo/wuPyih5lMF2GTHEuovLffiMueY="
	c.Assert(params["Signature"], Equals, expected)
}
