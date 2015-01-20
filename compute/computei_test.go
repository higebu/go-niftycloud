package compute_test

import (
	"crypto/rand"
	"fmt"

	"github.com/higebu/go-niftycloud/compute"
	"github.com/higebu/go-niftycloud/niftycloud"
	"github.com/higebu/go-niftycloud/testutil"
	. "gopkg.in/check.v1"
)

// NiftyServer represents an NIFTY Cloud server.
type NiftyServer struct {
	auth niftycloud.Auth
}

func (s *NiftyServer) SetUp(c *C) {
	auth, err := niftycloud.EnvAuth()
	if err != nil {
		c.Fatal(err.Error())
	}
	s.auth = auth
}

// Suite cost per run: 0.02 USD
var _ = Suite(&NiftyClientSuite{})

// NiftyClientSuite tests the client against a live NIFTY Cloud server.
type NiftyClientSuite struct {
	srv NiftyServer
	ClientTests
}

func (s *NiftyClientSuite) SetUpSuite(c *C) {
	if !testutil.Nifty {
		c.Skip("NiftyClientSuite tests not enabled")
	}
	s.srv.SetUp(c)
	s.compute = compute.NewWithClient(s.srv.auth, niftycloud.JPEast, testutil.DefaultClient)
}

// ClientTests defines integration tests designed to test the client.
// It is not used as a test suite in itself, but embedded within
// another type.
type ClientTests struct {
	compute *compute.Compute
}

var imageId = "ami-ccf405a5" // Ubuntu Maverick, i386, EBS store

// Cost: 0.00 USD
func (s *ClientTests) TestRunInstancesError(c *C) {
	options := compute.RunInstancesOptions{
		ImageId:      "ami-a6f504cf", // Ubuntu Maverick, i386, instance store
		InstanceType: "mini",
	}

	resp, err := s.compute.RunInstances(&options)

	c.Assert(resp, IsNil)
	c.Assert(err, ErrorMatches, "NMI.*root device.*not supported.*")

	computeerr, ok := err.(*compute.Error)
	c.Assert(ok, Equals, true)
	c.Assert(computeerr.StatusCode, Equals, 400)
	c.Assert(computeerr.Code, Equals, "UnsupportedOperation")
	c.Assert(computeerr.Message, Matches, "NMI.*root device.*not supported.*")
	c.Assert(computeerr.RequestId, Matches, ".+")
}

// Cost: 0.02 USD
func (s *ClientTests) TestRunAndTerminate(c *C) {
	options := compute.RunInstancesOptions{
		ImageId:      imageId,
		InstanceType: "mini",
	}
	resp1, err := s.compute.RunInstances(&options)
	c.Assert(err, IsNil)
	c.Check(resp1.ReservationId, Matches, "r-[0-9a-f]*")
	c.Check(resp1.OwnerId, Matches, "[0-9]+")
	c.Check(resp1.Instances, HasLen, 1)
	c.Check(resp1.Instances[0].InstanceType, Equals, "mini")

	instId := resp1.Instances[0].InstanceId

	resp2, err := s.compute.DescribeInstances([]string{instId}, nil)
	c.Assert(err, IsNil)
	if c.Check(resp2.Reservations, HasLen, 1) && c.Check(len(resp2.Reservations[0].Instances), Equals, 1) {
		inst := resp2.Reservations[0].Instances[0]
		c.Check(inst.InstanceId, Equals, instId)
	}

	resp3, err := s.compute.TerminateInstances([]string{instId})
	c.Assert(err, IsNil)
	c.Check(resp3.StateChanges, HasLen, 1)
	c.Check(resp3.StateChanges[0].InstanceId, Equals, instId)
	c.Check(resp3.StateChanges[0].CurrentState.Name, Equals, "shutting-down")
	c.Check(resp3.StateChanges[0].CurrentState.Code, Equals, 32)
}

// Cost: 0.00 USD
func (s *ClientTests) TestSecurityGroups(c *C) {
	name := "goamz-test"
	descr := "goamz security group for tests"

	// Clean it up, if a previous test left it around and avoid leaving it around.
	s.compute.DeleteSecurityGroup(compute.SecurityGroup{Name: name})
	defer s.compute.DeleteSecurityGroup(compute.SecurityGroup{Name: name})

	resp1, err := s.compute.CreateSecurityGroup(compute.SecurityGroup{Name: name, Description: descr})
	c.Assert(err, IsNil)
	c.Assert(resp1.RequestId, Matches, ".+")
	c.Assert(resp1.Name, Equals, name)
	c.Assert(resp1.Id, Matches, ".+")

	resp1, err = s.compute.CreateSecurityGroup(compute.SecurityGroup{Name: name, Description: descr})
	computeerr, _ := err.(*compute.Error)
	c.Assert(resp1, IsNil)
	c.Assert(computeerr, NotNil)
	c.Assert(computeerr.Code, Equals, "InvalidGroup.Duplicate")

	perms := []compute.IPPerm{{
		Protocol:  "tcp",
		FromPort:  0,
		ToPort:    1024,
		SourceIPs: []string{"127.0.0.1/24"},
	}}

	resp2, err := s.compute.AuthorizeSecurityGroup(compute.SecurityGroup{Name: name}, perms)
	c.Assert(err, IsNil)
	c.Assert(resp2.RequestId, Matches, ".+")

	resp3, err := s.compute.SecurityGroups(compute.SecurityGroupNames(name), nil)
	c.Assert(err, IsNil)
	c.Assert(resp3.RequestId, Matches, ".+")
	c.Assert(resp3.Groups, HasLen, 1)

	g0 := resp3.Groups[0]
	c.Assert(g0.Name, Equals, name)
	c.Assert(g0.Description, Equals, descr)
	c.Assert(g0.IPPerms, HasLen, 1)
	c.Assert(g0.IPPerms[0].Protocol, Equals, "tcp")
	c.Assert(g0.IPPerms[0].FromPort, Equals, 0)
	c.Assert(g0.IPPerms[0].ToPort, Equals, 1024)
	c.Assert(g0.IPPerms[0].SourceIPs, DeepEquals, []string{"127.0.0.1/24"})

	resp2, err = s.compute.DeleteSecurityGroup(compute.SecurityGroup{Name: name})
	c.Assert(err, IsNil)
	c.Assert(resp2.RequestId, Matches, ".+")
}

var sessionId = func() string {
	buf := make([]byte, 8)
	// if we have no randomness, we'll just make do, so ignore the error.
	rand.Read(buf)
	return fmt.Sprintf("%x", buf)
}()

// sessionName reutrns a name that is probably
// unique to this test session.
func sessionName(prefix string) string {
	return prefix + "-" + sessionId
}

var allRegions = []niftycloud.Region{
	niftycloud.JPEast,
	niftycloud.JPEast2,
	niftycloud.JPWest,
}

// Communicate with all NIFTY Cloud endpoints to see if they are alive.
func (s *ClientTests) TestRegions(c *C) {
	name := sessionName("goamz-region-test")
	perms := []compute.IPPerm{{
		Protocol:  "tcp",
		FromPort:  80,
		ToPort:    80,
		SourceIPs: []string{"127.0.0.1/32"},
	}}
	errs := make(chan error, len(allRegions))
	for _, region := range allRegions {
		go func(r niftycloud.Region) {
			e := compute.NewWithClient(s.compute.Auth, r, testutil.DefaultClient)
			_, err := e.AuthorizeSecurityGroup(compute.SecurityGroup{Name: name}, perms)
			errs <- err
		}(region)
	}
	for _ = range allRegions {
		err := <-errs
		if err != nil {
			compute_err, ok := err.(*compute.Error)
			if ok {
				c.Check(compute_err.Code, Matches, "InvalidGroup.NotFound")
			} else {
				c.Errorf("Non-Compute error: %s", err)
			}
		} else {
			c.Errorf("Test should have errored but it seems to have succeeded")
		}
	}
}
