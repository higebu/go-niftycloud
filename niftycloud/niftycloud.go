//
// go-niftycloud - Go packages to interact with NIFTY Cloud.
//
// Copyright (c) 2014 NIFTY Corp.
//
// Written by Yuya Kusakabe <kusakabe.yuya@nifty.co.jp>
//
package niftycloud

import (
	"errors"
	"os"
)

// Region defines the URLs where AWS services may be accessed.
//
// See http://goo.gl/d8BP1 for more details.
type Region struct {
	Name                 string // the canonical name of this region.
	ComputeEndpoint      string
	S3Endpoint           string
	S3LocationConstraint bool // true if this region requires a LocationConstraint declaration.
	S3LowercaseBucket    bool // true if the region requires bucket names to be lower case.
}

var JPEast = Region{
	"jp-east-1",
	"https://east-1.cp.cloud.nifty.com/api/",
	"https://ncss.nifty.com",
	false,
	false,
}

var JPEast2 = Region{
	"jp-east-2",
	"https://east-2.cp.cloud.nifty.com/api/",
	"https://ncss.nifty.com",
	false,
	false,
}

var JPEast3 = Region{
	"jp-east-3",
	"https://east-3.cp.cloud.nifty.com/api/",
	"https://ncss.nifty.com",
	false,
	false,
}

var JPWest = Region{
	"jp-west-1",
	"https://west-1.cp.cloud.nifty.com/api/",
	"https://west-1-ncss.nifty.com",
	true,
	true,
}

var USEast = Region{
	"us-east-1",
	"https://us-east-1.uscp.cloud.nifty.com/api/",
	"https://ncss.nifty.com",
	true,
	true,
}

var Regions = map[string]Region{
	JPEast.Name:  JPEast,
	JPEast2.Name: JPEast2,
	JPEast3.Name: JPEast3,
	JPWest.Name:  JPWest,
	USEast.Name:  USEast,
}

type Auth struct {
	AccessKey, SecretKey, Token string
}

var unreserved = make([]bool, 128)
var hex = "0123456789ABCDEF"

func init() {
	// RFC3986
	u := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890-_.~"
	for _, c := range u {
		unreserved[c] = true
	}
}

type credentials struct {
	Code            string
	LastUpdated     string
	Type            string
	AccessKeyId     string
	SecretAccessKey string
	Expiration      string
}

// GetAuth creates an Auth based on either passed in credentials,
// environment information or instance based role credentials.
func GetAuth(accessKey string, secretKey string) (auth Auth, err error) {
	// First try passed in credentials
	if accessKey != "" && secretKey != "" {
		return Auth{accessKey, secretKey, ""}, nil
	}

	// Next try to get auth from the environment
	auth, err = EnvAuth()
	if err == nil {
		// Found auth, return
		return
	}

	err = errors.New("No valid NIFTY Cloud authentication found")
	return
}

// EnvAuth creates an Auth based on environment information.
// The NIFTY_CLOUD_ACCESS_KEY_ID and NIFTY_CLOUD_SECRET_ACCESS_KEY environment
// For accounts that require a security token, it is read from AWS_SECURITY_TOKEN
// variables are used.
func EnvAuth() (auth Auth, err error) {
	auth.AccessKey = os.Getenv("NIFTY_CLOUD_ACCESS_KEY_ID")
	if auth.AccessKey == "" {
		auth.AccessKey = os.Getenv("NIFTY_CLOUD_ACCESS_KEY")
	}

	auth.SecretKey = os.Getenv("NIFTY_CLOUD_SECRET_ACCESS_KEY")
	if auth.SecretKey == "" {
		auth.SecretKey = os.Getenv("NIFTY_CLOUD_SECRET_KEY")
	}

	if auth.AccessKey == "" {
		err = errors.New("NIFTY_CLOUD_ACCESS_KEY_ID or NIFTY_CLOUD_ACCESS_KEY not found in environment")
	}
	if auth.SecretKey == "" {
		err = errors.New("NIFTY_CLOUD_SECRET_ACCESS_KEY or NIFTY_CLOUD_SECRET_KEY not found in environment")
	}
	return
}

// Encode takes a string and URI-encodes it in a way suitable
// to be used in NIFTY Cloud signatures.
func Encode(s string) string {
	encode := false
	for i := 0; i != len(s); i++ {
		c := s[i]
		if c > 127 || !unreserved[c] {
			encode = true
			break
		}
	}
	if !encode {
		return s
	}
	e := make([]byte, len(s)*3)
	ei := 0
	for i := 0; i != len(s); i++ {
		c := s[i]
		if c > 127 || !unreserved[c] {
			e[ei] = '%'
			e[ei+1] = hex[c>>4]
			e[ei+2] = hex[c&0xF]
			ei += 3
		} else {
			e[ei] = c
			ei += 1
		}
	}
	return string(e[:ei])
}
