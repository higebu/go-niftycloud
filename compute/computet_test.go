package compute_test

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/higebu/go-niftycloud/compute"
	"github.com/higebu/go-niftycloud/compute/computetest"
	"github.com/higebu/go-niftycloud/niftycloud"
	"github.com/higebu/go-niftycloud/testutil"
	. "gopkg.in/check.v1"
)

// LocalServer represents a local computetest fake server.
type LocalServer struct {
	auth   niftycloud.Auth
	region niftycloud.Region
	srv    *computetest.Server
}

func (s *LocalServer) SetUp(c *C) {
	srv, err := computetest.NewServer()
	c.Assert(err, IsNil)
	c.Assert(srv, NotNil)

	s.srv = srv
	s.region = niftycloud.Region{ComputeEndpoint: srv.URL()}
}

// LocalServerSuite defines tests that will run
// against the local computetest server. It includes
// selected tests from ClientTests;
// when the computetest functionality is sufficient, it should
// include all of them, and ClientTests can be simply embedded.
type LocalServerSuite struct {
	srv LocalServer
	ServerTests
	clientTests ClientTests
}

var _ = Suite(&LocalServerSuite{})

func (s *LocalServerSuite) SetUpSuite(c *C) {
	s.srv.SetUp(c)
	s.ServerTests.compute = compute.NewWithClient(s.srv.auth, s.srv.region, testutil.DefaultClient)
	s.clientTests.compute = compute.NewWithClient(s.srv.auth, s.srv.region, testutil.DefaultClient)
}

func (s *LocalServerSuite) TestRunAndTerminate(c *C) {
	s.clientTests.TestRunAndTerminate(c)
}

func (s *LocalServerSuite) TestSecurityGroups(c *C) {
	s.clientTests.TestSecurityGroups(c)
}

// TestUserData is not defined on ServerTests because it
// requires the computetest server to function.
func (s *LocalServerSuite) TestUserData(c *C) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	inst, err := s.compute.RunInstances(&compute.RunInstancesOptions{
		ImageId:      imageId,
		InstanceType: "mini",
		UserData:     data,
	})
	c.Assert(err, IsNil)
	c.Assert(inst, NotNil)

	id := inst.Instances[0].InstanceId

	defer s.compute.TerminateInstances([]string{id})

	tinst := s.srv.srv.Instance(id)
	c.Assert(tinst, NotNil)
	c.Assert(tinst.UserData, DeepEquals, data)
}

// NiftyServerSuite runs the computetest server tests against a live NIFTY Cloud server.
// It will only be activated if the -all flag is specified.
type NiftyServerSuite struct {
	srv NiftyServer
	ServerTests
}

var _ = Suite(&NiftyServerSuite{})

func (s *NiftyServerSuite) SetUpSuite(c *C) {
	if !testutil.Nifty {
		c.Skip("NiftyServerSuite tests not enabled")
	}
	s.srv.SetUp(c)
	s.ServerTests.compute = compute.NewWithClient(s.srv.auth, niftycloud.JPEast, testutil.DefaultClient)
}

// ServerTests defines a set of tests designed to test
// the computetest local fake NIFTY Cloud server.
// It is not used as a test suite in itself, but embedded within
// another type.
type ServerTests struct {
	compute *compute.Compute
}

func terminateInstances(c *C, e *compute.Compute, insts []*compute.Instance) {
	var ids []string
	for _, inst := range insts {
		if inst != nil {
			ids = append(ids, inst.InstanceId)
		}
	}
	_, err := e.TerminateInstances(ids)
	c.Check(err, IsNil, Commentf("%d INSTANCES LEFT RUNNING!!!", len(ids)))
}

func (s *ServerTests) makeTestGroup(c *C, name, descr string) compute.SecurityGroup {
	// Clean it up if a previous test left it around.
	_, err := s.compute.DeleteSecurityGroup(compute.SecurityGroup{Name: name})
	if err != nil && err.(*compute.Error).Code != "InvalidGroup.NotFound" {
		c.Fatalf("delete security group: %v", err)
	}

	resp, err := s.compute.CreateSecurityGroup(compute.SecurityGroup{Name: name, Description: descr})
	c.Assert(err, IsNil)
	c.Assert(resp.Name, Equals, name)
	return resp.SecurityGroup
}

func (s *ServerTests) TestIPPerms(c *C) {
	g0 := s.makeTestGroup(c, "goamz-test0", "computetest group 0")
	defer s.compute.DeleteSecurityGroup(g0)

	g1 := s.makeTestGroup(c, "goamz-test1", "computetest group 1")
	defer s.compute.DeleteSecurityGroup(g1)

	resp, err := s.compute.SecurityGroups([]compute.SecurityGroup{g0, g1}, nil)
	c.Assert(err, IsNil)
	c.Assert(resp.Groups, HasLen, 2)
	c.Assert(resp.Groups[0].IPPerms, HasLen, 0)
	c.Assert(resp.Groups[1].IPPerms, HasLen, 0)

	ownerId := resp.Groups[0].OwnerId

	// test some invalid parameters
	// TODO more
	_, err = s.compute.AuthorizeSecurityGroup(g0, []compute.IPPerm{{
		Protocol:  "tcp",
		FromPort:  0,
		ToPort:    1024,
		SourceIPs: []string{"z127.0.0.1/24"},
	}})
	c.Assert(err, NotNil)
	c.Check(err.(*compute.Error).Code, Equals, "InvalidPermission.Malformed")

	// Check that AuthorizeSecurityGroup adds the correct authorizations.
	_, err = s.compute.AuthorizeSecurityGroup(g0, []compute.IPPerm{{
		Protocol:  "tcp",
		FromPort:  2000,
		ToPort:    2001,
		SourceIPs: []string{"127.0.0.0/24"},
		SourceGroups: []compute.UserSecurityGroup{{
			Name: g1.Name,
		}, {
			Id: g0.Id,
		}},
	}, {
		Protocol:  "tcp",
		FromPort:  2000,
		ToPort:    2001,
		SourceIPs: []string{"200.1.1.34/32"},
	}})
	c.Assert(err, IsNil)

	resp, err = s.compute.SecurityGroups([]compute.SecurityGroup{g0}, nil)
	c.Assert(err, IsNil)
	c.Assert(resp.Groups, HasLen, 1)
	c.Assert(resp.Groups[0].IPPerms, HasLen, 1)

	perm := resp.Groups[0].IPPerms[0]
	srcg := perm.SourceGroups
	c.Assert(srcg, HasLen, 2)

	// Normalize so we don't care about returned order.
	if srcg[0].Name == g1.Name {
		srcg[0], srcg[1] = srcg[1], srcg[0]
	}
	c.Check(srcg[0].Name, Equals, g0.Name)
	c.Check(srcg[0].Id, Equals, g0.Id)
	c.Check(srcg[0].OwnerId, Equals, ownerId)
	c.Check(srcg[1].Name, Equals, g1.Name)
	c.Check(srcg[1].Id, Equals, g1.Id)
	c.Check(srcg[1].OwnerId, Equals, ownerId)

	sort.Strings(perm.SourceIPs)
	c.Check(perm.SourceIPs, DeepEquals, []string{"127.0.0.0/24", "200.1.1.34/32"})

	// Check that we can't delete g1 (because g0 is using it)
	_, err = s.compute.DeleteSecurityGroup(g1)
	c.Assert(err, NotNil)
	c.Check(err.(*compute.Error).Code, Equals, "InvalidGroup.InUse")

	_, err = s.compute.RevokeSecurityGroup(g0, []compute.IPPerm{{
		Protocol:     "tcp",
		FromPort:     2000,
		ToPort:       2001,
		SourceGroups: []compute.UserSecurityGroup{{Id: g1.Id}},
	}, {
		Protocol:  "tcp",
		FromPort:  2000,
		ToPort:    2001,
		SourceIPs: []string{"200.1.1.34/32"},
	}})
	c.Assert(err, IsNil)

	resp, err = s.compute.SecurityGroups([]compute.SecurityGroup{g0}, nil)
	c.Assert(err, IsNil)
	c.Assert(resp.Groups, HasLen, 1)
	c.Assert(resp.Groups[0].IPPerms, HasLen, 1)

	perm = resp.Groups[0].IPPerms[0]
	srcg = perm.SourceGroups
	c.Assert(srcg, HasLen, 1)
	c.Check(srcg[0].Name, Equals, g0.Name)
	c.Check(srcg[0].Id, Equals, g0.Id)
	c.Check(srcg[0].OwnerId, Equals, ownerId)

	c.Check(perm.SourceIPs, DeepEquals, []string{"127.0.0.0/24"})

	// We should be able to delete g1 now because we've removed its only use.
	_, err = s.compute.DeleteSecurityGroup(g1)
	c.Assert(err, IsNil)

	_, err = s.compute.DeleteSecurityGroup(g0)
	c.Assert(err, IsNil)

	f := compute.NewFilter()
	f.Add("group-id", g0.Id, g1.Id)
	resp, err = s.compute.SecurityGroups(nil, f)
	c.Assert(err, IsNil)
	c.Assert(resp.Groups, HasLen, 0)
}

func (s *ServerTests) TestDuplicateIPPerm(c *C) {
	name := "goamz-test"
	descr := "goamz security group for tests"

	// Clean it up, if a previous test left it around and avoid leaving it around.
	s.compute.DeleteSecurityGroup(compute.SecurityGroup{Name: name})
	defer s.compute.DeleteSecurityGroup(compute.SecurityGroup{Name: name})

	resp1, err := s.compute.CreateSecurityGroup(compute.SecurityGroup{Name: name, Description: descr})
	c.Assert(err, IsNil)
	c.Assert(resp1.Name, Equals, name)

	perms := []compute.IPPerm{{
		Protocol:  "tcp",
		FromPort:  200,
		ToPort:    1024,
		SourceIPs: []string{"127.0.0.1/24"},
	}, {
		Protocol:  "tcp",
		FromPort:  0,
		ToPort:    100,
		SourceIPs: []string{"127.0.0.1/24"},
	}}

	_, err = s.compute.AuthorizeSecurityGroup(compute.SecurityGroup{Name: name}, perms[0:1])
	c.Assert(err, IsNil)

	_, err = s.compute.AuthorizeSecurityGroup(compute.SecurityGroup{Name: name}, perms[0:2])
	c.Assert(err, ErrorMatches, `.*\(InvalidPermission.Duplicate\)`)
}

type filterSpec struct {
	name   string
	values []string
}

func idsOnly(gs []compute.SecurityGroup) []compute.SecurityGroup {
	for i := range gs {
		gs[i].Name = ""
	}
	return gs
}

func namesOnly(gs []compute.SecurityGroup) []compute.SecurityGroup {
	for i := range gs {
		gs[i].Id = ""
	}
	return gs
}

func (s *ServerTests) TestGroupFiltering(c *C) {
	g := make([]compute.SecurityGroup, 4)
	for i := range g {
		resp, err := s.compute.CreateSecurityGroup(compute.SecurityGroup{Name: sessionName(fmt.Sprintf("testgroup%d", i)), Description: fmt.Sprintf("testdescription%d", i)})
		c.Assert(err, IsNil)
		g[i] = resp.SecurityGroup
		c.Logf("group %d: %v", i, g[i])
		defer s.compute.DeleteSecurityGroup(g[i])
	}

	perms := [][]compute.IPPerm{
		{{
			Protocol:  "tcp",
			FromPort:  100,
			ToPort:    200,
			SourceIPs: []string{"1.2.3.4/32"},
		}},
		{{
			Protocol:     "tcp",
			FromPort:     200,
			ToPort:       300,
			SourceGroups: []compute.UserSecurityGroup{{Id: g[1].Id}},
		}},
		{{
			Protocol:     "udp",
			FromPort:     200,
			ToPort:       400,
			SourceGroups: []compute.UserSecurityGroup{{Id: g[1].Id}},
		}},
	}
	for i, ps := range perms {
		_, err := s.compute.AuthorizeSecurityGroup(g[i], ps)
		c.Assert(err, IsNil)
	}

	groups := func(indices ...int) (gs []compute.SecurityGroup) {
		for _, index := range indices {
			gs = append(gs, g[index])
		}
		return
	}

	type groupTest struct {
		about      string
		groups     []compute.SecurityGroup // groupIds argument to SecurityGroups method.
		filters    []filterSpec            // filters argument to SecurityGroups method.
		results    []compute.SecurityGroup // set of expected result groups.
		allowExtra bool                    // specified results may be incomplete.
		err        string                  // expected error.
	}
	filterCheck := func(name, val string, gs []compute.SecurityGroup) groupTest {
		return groupTest{
			about:      "filter check " + name,
			filters:    []filterSpec{{name, []string{val}}},
			results:    gs,
			allowExtra: true,
		}
	}
	tests := []groupTest{
		{
			about:      "check that SecurityGroups returns all groups",
			results:    groups(0, 1, 2, 3),
			allowExtra: true,
		}, {
			about:   "check that specifying two group ids returns them",
			groups:  idsOnly(groups(0, 2)),
			results: groups(0, 2),
		}, {
			about:   "check that specifying names only works",
			groups:  namesOnly(groups(0, 2)),
			results: groups(0, 2),
		}, {
			about:  "check that specifying a non-existent group id gives an error",
			groups: append(groups(0), compute.SecurityGroup{Id: "sg-eeeeeeeee"}),
			err:    `.*\(InvalidGroup\.NotFound\)`,
		}, {
			about: "check that a filter allowed two groups returns both of them",
			filters: []filterSpec{
				{"group-id", []string{g[0].Id, g[2].Id}},
			},
			results: groups(0, 2),
		},
		{
			about:  "check that the previous filter works when specifying a list of ids",
			groups: groups(1, 2),
			filters: []filterSpec{
				{"group-id", []string{g[0].Id, g[2].Id}},
			},
			results: groups(2),
		}, {
			about: "check that a filter allowing no groups returns none",
			filters: []filterSpec{
				{"group-id", []string{"sg-eeeeeeeee"}},
			},
		},
		filterCheck("description", "testdescription1", groups(1)),
		filterCheck("group-name", g[2].Name, groups(2)),
		filterCheck("ip-permission.cidr", "1.2.3.4/32", groups(0)),
		filterCheck("ip-permission.group-name", g[1].Name, groups(1, 2)),
		filterCheck("ip-permission.protocol", "udp", groups(2)),
		filterCheck("ip-permission.from-port", "200", groups(1, 2)),
		filterCheck("ip-permission.to-port", "200", groups(0)),
		// TODO owner-id
	}
	for i, t := range tests {
		c.Logf("%d. %s", i, t.about)
		var f *compute.Filter
		if t.filters != nil {
			f = compute.NewFilter()
			for _, spec := range t.filters {
				f.Add(spec.name, spec.values...)
			}
		}
		resp, err := s.compute.SecurityGroups(t.groups, f)
		if t.err != "" {
			c.Check(err, ErrorMatches, t.err)
			continue
		}
		c.Assert(err, IsNil)
		groups := make(map[string]*compute.SecurityGroup)
		for j := range resp.Groups {
			group := &resp.Groups[j].SecurityGroup
			c.Check(groups[group.Id], IsNil, Commentf("duplicate group id: %q", group.Id))

			groups[group.Id] = group
		}
		// If extra groups may be returned, eliminate all groups that
		// we did not create in this session apart from the default group.
		if t.allowExtra {
			namePat := regexp.MustCompile(sessionName("testgroup[0-9]"))
			for id, g := range groups {
				if !namePat.MatchString(g.Name) {
					delete(groups, id)
				}
			}
		}
		c.Check(groups, HasLen, len(t.results))
		for j, g := range t.results {
			rg := groups[g.Id]
			c.Assert(rg, NotNil, Commentf("group %d (%v) not found; got %#v", j, g, groups))
			c.Check(rg.Name, Equals, g.Name, Commentf("group %d (%v)", j, g))
		}
	}
}
