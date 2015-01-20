package compute_test

import (
	"testing"

	"github.com/higebu/go-niftycloud/compute"
	"github.com/higebu/go-niftycloud/niftycloud"
	"github.com/higebu/go-niftycloud/testutil"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

var _ = Suite(&S{})

type S struct {
	compute *compute.Compute
}

var testServer = testutil.NewHTTPServer()

func (s *S) SetUpSuite(c *C) {
	testServer.Start()
	auth := niftycloud.Auth{AccessKey: "abc", SecretKey: "123"}
	s.compute = compute.NewWithClient(
		auth,
		niftycloud.Region{ComputeEndpoint: testServer.URL},
		testutil.DefaultClient,
	)
}

func (s *S) TearDownTest(c *C) {
	testServer.Flush()
}

func (s *S) TestRunInstancesErrorDump(c *C) {
	testServer.Response(400, nil, ErrorDump)

	options := compute.RunInstancesOptions{
		ImageId:      "29", // CentOS 6.4 64bit Plain, instance store
		InstanceType: "mini",
	}

	msg := `NMIs with an instance-store root device are not supported for the instance type 'mini'\.`

	resp, err := s.compute.RunInstances(&options)

	testServer.WaitRequest()

	c.Assert(resp, IsNil)
	c.Assert(err, ErrorMatches, msg+` \(UnsupportedOperation\)`)

	computeerr, ok := err.(*compute.Error)
	c.Assert(ok, Equals, true)
	c.Assert(computeerr.StatusCode, Equals, 400)
	c.Assert(computeerr.Code, Equals, "UnsupportedOperation")
	c.Assert(computeerr.Message, Matches, msg)
	c.Assert(computeerr.RequestId, Equals, "0503f4e9-bbd6-483c-b54f-c4ae9f3b30f4")
}

func (s *S) TestRunInstancesErrorWithoutXML(c *C) {
	testServer.Responses(5, 500, nil, "")
	options := compute.RunInstancesOptions{ImageId: "image-id"}

	resp, err := s.compute.RunInstances(&options)

	testServer.WaitRequest()

	c.Assert(resp, IsNil)
	c.Assert(err, ErrorMatches, "500 Internal Server Error")

	computeerr, ok := err.(*compute.Error)
	c.Assert(ok, Equals, true)
	c.Assert(computeerr.StatusCode, Equals, 500)
	c.Assert(computeerr.Code, Equals, "")
	c.Assert(computeerr.Message, Equals, "500 Internal Server Error")
	c.Assert(computeerr.RequestId, Equals, "")
}

func (s *S) TestRunInstancesExample(c *C) {
	testServer.Response(200, nil, RunInstancesExample)

	options := compute.RunInstancesOptions{
		KeyName:      "my-keys",
		ImageId:      "image-id",
		InstanceType: "inst-type",
		SecurityGroups: []compute.SecurityGroup{
			{Name: "g1"},
			{Id: "g2"},
			{Name: "g3"},
			{Id: "g4"}},
		UserData:              []byte("1234"),
		DisableAPITermination: true,
	}
	resp, err := s.compute.RunInstances(&options)

	req := testServer.WaitRequest()
	c.Assert(req.Form["Action"], DeepEquals, []string{"RunInstances"})
	c.Assert(req.Form["ImageId"], DeepEquals, []string{"image-id"})
	c.Assert(req.Form["KeyName"], DeepEquals, []string{"my-keys"})
	c.Assert(req.Form["InstanceType"], DeepEquals, []string{"inst-type"})
	c.Assert(req.Form["SecurityGroup.1"], DeepEquals, []string{"g1"})
	c.Assert(req.Form["SecurityGroup.2"], DeepEquals, []string{"g3"})
	c.Assert(req.Form["SecurityGroupId.1"], DeepEquals, []string{"g2"})
	c.Assert(req.Form["SecurityGroupId.2"], DeepEquals, []string{"g4"})
	c.Assert(req.Form["UserData"], DeepEquals, []string{"MTIzNA=="})
	c.Assert(req.Form["DisableApiTermination"], DeepEquals, []string{"true"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
	c.Assert(resp.ReservationId, Equals, "r-47a5402e")
	c.Assert(resp.OwnerId, Equals, "999988887777")
	c.Assert(resp.SecurityGroups, DeepEquals, []compute.SecurityGroup{{Name: "default", Id: "sg-67ad940e"}})
	c.Assert(resp.Instances, HasLen, 3)

	i0 := resp.Instances[0]
	c.Assert(i0.InstanceId, Equals, "2ba64342")
	c.Assert(i0.InstanceType, Equals, "small")
	c.Assert(i0.ImageId, Equals, "29")
	c.Assert(i0.KeyName, Equals, "example-key-name")

	i1 := resp.Instances[1]
	c.Assert(i1.InstanceId, Equals, "2bc64242")
	c.Assert(i1.InstanceType, Equals, "small")
	c.Assert(i1.ImageId, Equals, "29")
	c.Assert(i1.KeyName, Equals, "example-key-name")

	i2 := resp.Instances[2]
	c.Assert(i2.InstanceId, Equals, "2be64332")
	c.Assert(i2.InstanceType, Equals, "small")
	c.Assert(i2.ImageId, Equals, "29")
	c.Assert(i2.KeyName, Equals, "example-key-name")
}

func (s *S) TestTerminateInstancesExample(c *C) {
	testServer.Response(200, nil, TerminateInstancesExample)

	resp, err := s.compute.TerminateInstances([]string{"i-1", "i-2"})

	req := testServer.WaitRequest()
	c.Assert(req.Form["Action"], DeepEquals, []string{"TerminateInstances"})
	c.Assert(req.Form["InstanceId.1"], DeepEquals, []string{"i-1"})
	c.Assert(req.Form["InstanceId.2"], DeepEquals, []string{"i-2"})
	c.Assert(req.Form["UserData"], IsNil)
	c.Assert(req.Form["DisableApiTermination"], IsNil)

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
	c.Assert(resp.StateChanges, HasLen, 1)
	c.Assert(resp.StateChanges[0].InstanceId, Equals, "3ea74257")
	c.Assert(resp.StateChanges[0].CurrentState.Code, Equals, 32)
	c.Assert(resp.StateChanges[0].CurrentState.Name, Equals, "shutting-down")
	c.Assert(resp.StateChanges[0].PreviousState.Code, Equals, 16)
	c.Assert(resp.StateChanges[0].PreviousState.Name, Equals, "running")
}

func (s *S) TestDescribeInstancesExample1(c *C) {
	testServer.Response(200, nil, DescribeInstancesExample1)

	filter := compute.NewFilter()
	filter.Add("key1", "value1")
	filter.Add("key2", "value2", "value3")

	resp, err := s.compute.DescribeInstances([]string{"i-1", "i-2"}, nil)

	req := testServer.WaitRequest()
	c.Assert(req.Form["Action"], DeepEquals, []string{"DescribeInstances"})
	c.Assert(req.Form["InstanceId.1"], DeepEquals, []string{"i-1"})
	c.Assert(req.Form["InstanceId.2"], DeepEquals, []string{"i-2"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "98e3c9a4-848c-4d6d-8e8a-b1bdEXAMPLE")
	c.Assert(resp.Reservations, HasLen, 2)

	r0 := resp.Reservations[0]
	c.Assert(r0.ReservationId, Equals, "r-b27e30d9")
	c.Assert(r0.OwnerId, Equals, "999988887777")
	c.Assert(r0.RequesterId, Equals, "854251627541")
	c.Assert(r0.SecurityGroups, DeepEquals, []compute.SecurityGroup{{Name: "default", Id: "sg-67ad940e"}})
	c.Assert(r0.Instances, HasLen, 1)

	r0i := r0.Instances[0]
	c.Assert(r0i.InstanceId, Equals, "c5cd56af")
}

func (s *S) TestDescribeInstancesExample2(c *C) {
	testServer.Response(200, nil, DescribeInstancesExample2)

	filter := compute.NewFilter()
	filter.Add("key1", "value1")
	filter.Add("key2", "value2", "value3")

	resp, err := s.compute.DescribeInstances([]string{"i-1", "i-2"}, filter)

	req := testServer.WaitRequest()
	c.Assert(req.Form["Action"], DeepEquals, []string{"DescribeInstances"})
	c.Assert(req.Form["InstanceId.1"], DeepEquals, []string{"i-1"})
	c.Assert(req.Form["InstanceId.2"], DeepEquals, []string{"i-2"})
	c.Assert(req.Form["Filter.1.Name"], DeepEquals, []string{"key1"})
	c.Assert(req.Form["Filter.1.Value.1"], DeepEquals, []string{"value1"})
	c.Assert(req.Form["Filter.1.Value.2"], IsNil)
	c.Assert(req.Form["Filter.2.Name"], DeepEquals, []string{"key2"})
	c.Assert(req.Form["Filter.2.Value.1"], DeepEquals, []string{"value2"})
	c.Assert(req.Form["Filter.2.Value.2"], DeepEquals, []string{"value3"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
	c.Assert(resp.Reservations, HasLen, 1)

	r0 := resp.Reservations[0]
	r0i := r0.Instances[0]
	c.Assert(r0i.State.Code, Equals, 16)
	c.Assert(r0i.State.Name, Equals, "running")
}

func (s *S) TestCreateImageExample(c *C) {
	testServer.Response(200, nil, CreateImageExample)

	options := &compute.CreateImage{
		InstanceId:  "123456",
		Name:        "foo",
		Description: "Test CreateImage",
		NoReboot:    true,
		BlockDevices: []compute.BlockDeviceMapping{
			{DeviceName: "/dev/sdb", VirtualName: "ephemeral0"},
			{DeviceName: "/dev/sdc", SnapshotId: "snap-a08912c9", DeleteOnTermination: true},
		},
	}

	resp, err := s.compute.CreateImage(options)

	req := testServer.WaitRequest()
	c.Assert(req.Form["Action"], DeepEquals, []string{"CreateImage"})
	c.Assert(req.Form["InstanceId"], DeepEquals, []string{options.InstanceId})
	c.Assert(req.Form["Name"], DeepEquals, []string{options.Name})
	c.Assert(req.Form["Description"], DeepEquals, []string{options.Description})
	c.Assert(req.Form["NoReboot"], DeepEquals, []string{"true"})
	c.Assert(req.Form["BlockDeviceMapping.1.DeviceName"], DeepEquals, []string{"/dev/sdb"})
	c.Assert(req.Form["BlockDeviceMapping.1.VirtualName"], DeepEquals, []string{"ephemeral0"})
	c.Assert(req.Form["BlockDeviceMapping.2.DeviceName"], DeepEquals, []string{"/dev/sdc"})
	c.Assert(req.Form["BlockDeviceMapping.2.Ebs.SnapshotId"], DeepEquals, []string{"snap-a08912c9"})
	c.Assert(req.Form["BlockDeviceMapping.2.Ebs.DeleteOnTermination"], DeepEquals, []string{"true"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
	c.Assert(resp.ImageId, Equals, "32")
}

func (s *S) TestDescribeImagesExample(c *C) {
	testServer.Response(200, nil, DescribeImagesExample)

	filter := compute.NewFilter()
	filter.Add("key1", "value1")
	filter.Add("key2", "value2", "value3")

	resp, err := s.compute.Images([]string{"ami-1", "ami-2"}, filter)

	req := testServer.WaitRequest()
	c.Assert(req.Form["Action"], DeepEquals, []string{"DescribeImages"})
	c.Assert(req.Form["ImageId.1"], DeepEquals, []string{"ami-1"})
	c.Assert(req.Form["ImageId.2"], DeepEquals, []string{"ami-2"})
	c.Assert(req.Form["Filter.1.Name"], DeepEquals, []string{"key1"})
	c.Assert(req.Form["Filter.1.Value.1"], DeepEquals, []string{"value1"})
	c.Assert(req.Form["Filter.1.Value.2"], IsNil)
	c.Assert(req.Form["Filter.2.Name"], DeepEquals, []string{"key2"})
	c.Assert(req.Form["Filter.2.Value.1"], DeepEquals, []string{"value2"})
	c.Assert(req.Form["Filter.2.Value.2"], DeepEquals, []string{"value3"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "4a4a27a2-2e7c-475d-b35b-ca822EXAMPLE")
	c.Assert(resp.Images, HasLen, 1)

	i0 := resp.Images[0]
	c.Assert(i0.Id, Equals, "29")
	c.Assert(i0.Type, Equals, "machine")
	c.Assert(i0.Name, Equals, "CentOS 6.4 64bit Plain")
	c.Assert(i0.Description, Equals, "")
	c.Assert(i0.Location, Equals, "")
	c.Assert(i0.State, Equals, "available")
	c.Assert(i0.OwnerId, Equals, "niftycloud")
	c.Assert(i0.OwnerAlias, Equals, "ニフティ株式会社")
	c.Assert(i0.Architecture, Equals, "x86_64")
	c.Assert(i0.RootDeviceType, Equals, "disk")
	c.Assert(i0.RootDeviceName, Equals, "")

	testServer.Response(200, nil, DescribeImagesExample)
	resp2, err := s.compute.ImagesByOwners([]string{"1", "2"}, []string{"niftycloud", "id2"}, filter)

	req2 := testServer.WaitRequest()
	c.Assert(req2.Form["Action"], DeepEquals, []string{"DescribeImages"})
	c.Assert(req2.Form["ImageId.1"], DeepEquals, []string{"1"})
	c.Assert(req2.Form["ImageId.2"], DeepEquals, []string{"2"})
	c.Assert(req2.Form["Owner.1"], DeepEquals, []string{"niftycloud"})
	c.Assert(req2.Form["Owner.2"], DeepEquals, []string{"id2"})
	c.Assert(req2.Form["Filter.1.Name"], DeepEquals, []string{"key1"})
	c.Assert(req2.Form["Filter.1.Value.1"], DeepEquals, []string{"value1"})
	c.Assert(req2.Form["Filter.1.Value.2"], IsNil)
	c.Assert(req2.Form["Filter.2.Name"], DeepEquals, []string{"key2"})
	c.Assert(req2.Form["Filter.2.Value.1"], DeepEquals, []string{"value2"})
	c.Assert(req2.Form["Filter.2.Value.2"], DeepEquals, []string{"value3"})

	c.Assert(err, IsNil)
	c.Assert(resp2.RequestId, Equals, "4a4a27a2-2e7c-475d-b35b-ca822EXAMPLE")
	c.Assert(resp2.Images, HasLen, 1)

	i1 := resp2.Images[0]
	c.Assert(i1.Id, Equals, "29")
	c.Assert(i1.Type, Equals, "machine")
	c.Assert(i1.Name, Equals, "CentOS 6.4 64bit Plain")
	c.Assert(i1.Description, Equals, "")
	c.Assert(i1.Location, Equals, "")
	c.Assert(i1.State, Equals, "available")
	c.Assert(i1.OwnerId, Equals, "niftycloud")
	c.Assert(i1.OwnerAlias, Equals, "ニフティ株式会社")
	c.Assert(i1.Architecture, Equals, "x86_64")
	c.Assert(i1.RootDeviceType, Equals, "disk")
	c.Assert(i1.RootDeviceName, Equals, "")
}

func (s *S) TestModifyImageAttributeExample(c *C) {
	testServer.Response(200, nil, ModifyImageAttributeExample)

	options := compute.ModifyImageAttribute{
		Description: "Test Description",
	}

	resp, err := s.compute.ModifyImageAttribute("32", &options)

	req := testServer.WaitRequest()
	c.Assert(req.Form["Action"], DeepEquals, []string{"ModifyImageAttribute"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
}

func (s *S) TestModifyImageAttributeExample_complex(c *C) {
	testServer.Response(200, nil, ModifyImageAttributeExample)

	options := compute.ModifyImageAttribute{
		AddUsers:     []string{"u1", "u2"},
		RemoveUsers:  []string{"u3"},
		AddGroups:    []string{"g1", "g3"},
		RemoveGroups: []string{"g2"},
		Description:  "Test Description",
	}

	resp, err := s.compute.ModifyImageAttribute("32", &options)

	req := testServer.WaitRequest()
	c.Assert(req.Form["Action"], DeepEquals, []string{"ModifyImageAttribute"})
	c.Assert(req.Form["LaunchPermission.Add.1.UserId"], DeepEquals, []string{"u1"})
	c.Assert(req.Form["LaunchPermission.Add.2.UserId"], DeepEquals, []string{"u2"})
	c.Assert(req.Form["LaunchPermission.Remove.1.UserId"], DeepEquals, []string{"u3"})
	c.Assert(req.Form["LaunchPermission.Add.1.Group"], DeepEquals, []string{"g1"})
	c.Assert(req.Form["LaunchPermission.Add.2.Group"], DeepEquals, []string{"g3"})
	c.Assert(req.Form["LaunchPermission.Remove.1.Group"], DeepEquals, []string{"g2"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
}

func (s *S) TestCreateSecurityGroupExample(c *C) {
	testServer.Response(200, nil, CreateSecurityGroupExample)

	resp, err := s.compute.CreateSecurityGroup(compute.SecurityGroup{Name: "websrv", Description: "Web Servers"})

	req := testServer.WaitRequest()
	c.Assert(req.Form["Action"], DeepEquals, []string{"CreateSecurityGroup"})
	c.Assert(req.Form["GroupName"], DeepEquals, []string{"websrv"})
	c.Assert(req.Form["GroupDescription"], DeepEquals, []string{"Web Servers"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
	c.Assert(resp.Name, Equals, "websrv")
	c.Assert(resp.Id, Equals, "sg-67ad940e")
}

func (s *S) TestDescribeSecurityGroupsExample(c *C) {
	testServer.Response(200, nil, DescribeSecurityGroupsExample)

	resp, err := s.compute.SecurityGroups([]compute.SecurityGroup{{Name: "WebServers"}, {Name: "RangedPortsBySource"}}, nil)

	req := testServer.WaitRequest()
	c.Assert(req.Form["Action"], DeepEquals, []string{"DescribeSecurityGroups"})
	c.Assert(req.Form["GroupName.1"], DeepEquals, []string{"WebServers"})
	c.Assert(req.Form["GroupName.2"], DeepEquals, []string{"RangedPortsBySource"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
	c.Assert(resp.Groups, HasLen, 2)

	g0 := resp.Groups[0]
	c.Assert(g0.OwnerId, Equals, "999988887777")
	c.Assert(g0.Name, Equals, "WebServers")
	c.Assert(g0.Id, Equals, "sg-67ad940e")
	c.Assert(g0.Description, Equals, "Web Servers")
	c.Assert(g0.IPPerms, HasLen, 1)

	g0ipp := g0.IPPerms[0]
	c.Assert(g0ipp.Protocol, Equals, "tcp")
	c.Assert(g0ipp.FromPort, Equals, 80)
	c.Assert(g0ipp.ToPort, Equals, 80)
	c.Assert(g0ipp.SourceIPs, DeepEquals, []string{"0.0.0.0/0"})

	g1 := resp.Groups[1]
	c.Assert(g1.OwnerId, Equals, "999988887777")
	c.Assert(g1.Name, Equals, "RangedPortsBySource")
	c.Assert(g1.Id, Equals, "sg-76abc467")
	c.Assert(g1.Description, Equals, "Group A")
	c.Assert(g1.IPPerms, HasLen, 1)

	g1ipp := g1.IPPerms[0]
	c.Assert(g1ipp.Protocol, Equals, "tcp")
	c.Assert(g1ipp.FromPort, Equals, 6000)
	c.Assert(g1ipp.ToPort, Equals, 7000)
	c.Assert(g1ipp.SourceIPs, IsNil)
}

func (s *S) TestDescribeSecurityGroupsExampleWithFilter(c *C) {
	testServer.Response(200, nil, DescribeSecurityGroupsExample)

	filter := compute.NewFilter()
	filter.Add("ip-permission.protocol", "tcp")
	filter.Add("ip-permission.from-port", "22")
	filter.Add("ip-permission.to-port", "22")
	filter.Add("ip-permission.group-name", "app_server_group", "database_group")

	_, err := s.compute.SecurityGroups(nil, filter)

	req := testServer.WaitRequest()
	c.Assert(req.Form["Action"], DeepEquals, []string{"DescribeSecurityGroups"})
	c.Assert(req.Form["Filter.1.Name"], DeepEquals, []string{"ip-permission.from-port"})
	c.Assert(req.Form["Filter.1.Value.1"], DeepEquals, []string{"22"})
	c.Assert(req.Form["Filter.2.Name"], DeepEquals, []string{"ip-permission.group-name"})
	c.Assert(req.Form["Filter.2.Value.1"], DeepEquals, []string{"app_server_group"})
	c.Assert(req.Form["Filter.2.Value.2"], DeepEquals, []string{"database_group"})
	c.Assert(req.Form["Filter.3.Name"], DeepEquals, []string{"ip-permission.protocol"})
	c.Assert(req.Form["Filter.3.Value.1"], DeepEquals, []string{"tcp"})
	c.Assert(req.Form["Filter.4.Name"], DeepEquals, []string{"ip-permission.to-port"})
	c.Assert(req.Form["Filter.4.Value.1"], DeepEquals, []string{"22"})

	c.Assert(err, IsNil)
}

func (s *S) TestDescribeSecurityGroupsDumpWithGroup(c *C) {
	testServer.Response(200, nil, DescribeSecurityGroupsDump)

	resp, err := s.compute.SecurityGroups(nil, nil)

	req := testServer.WaitRequest()
	c.Assert(req.Form["Action"], DeepEquals, []string{"DescribeSecurityGroups"})
	c.Assert(err, IsNil)
	c.Check(resp.Groups, HasLen, 1)
	c.Check(resp.Groups[0].IPPerms, HasLen, 2)

	ipp0 := resp.Groups[0].IPPerms[0]
	c.Assert(ipp0.SourceIPs, IsNil)
	c.Check(ipp0.Protocol, Equals, "icmp")
	c.Assert(ipp0.SourceGroups, HasLen, 1)
	c.Check(ipp0.SourceGroups[0].OwnerId, Equals, "12345")
	c.Check(ipp0.SourceGroups[0].Name, Equals, "default")
	c.Check(ipp0.SourceGroups[0].Id, Equals, "sg-67ad940e")

	ipp1 := resp.Groups[0].IPPerms[1]
	c.Check(ipp1.Protocol, Equals, "tcp")
	c.Assert(ipp0.SourceIPs, IsNil)
	c.Assert(ipp0.SourceGroups, HasLen, 1)
	c.Check(ipp1.SourceGroups[0].Id, Equals, "sg-76abc467")
	c.Check(ipp1.SourceGroups[0].OwnerId, Equals, "12345")
	c.Check(ipp1.SourceGroups[0].Name, Equals, "other")
}

func (s *S) TestDeleteSecurityGroupExample(c *C) {
	testServer.Response(200, nil, DeleteSecurityGroupExample)

	resp, err := s.compute.DeleteSecurityGroup(compute.SecurityGroup{Name: "websrv"})
	req := testServer.WaitRequest()

	c.Assert(req.Form["Action"], DeepEquals, []string{"DeleteSecurityGroup"})
	c.Assert(req.Form["GroupName"], DeepEquals, []string{"websrv"})
	c.Assert(req.Form["GroupId"], IsNil)
	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
}

func (s *S) TestDeleteSecurityGroupExampleWithId(c *C) {
	testServer.Response(200, nil, DeleteSecurityGroupExample)

	// ignore return and error - we're only want to check the parameter handling.
	s.compute.DeleteSecurityGroup(compute.SecurityGroup{Id: "sg-67ad940e", Name: "ignored"})
	req := testServer.WaitRequest()

	c.Assert(req.Form["GroupName"], IsNil)
	c.Assert(req.Form["GroupId"], DeepEquals, []string{"sg-67ad940e"})
}

func (s *S) TestAuthorizeSecurityGroupExample1(c *C) {
	testServer.Response(200, nil, AuthorizeSecurityGroupIngressExample)

	perms := []compute.IPPerm{{
		Protocol:  "tcp",
		FromPort:  80,
		ToPort:    80,
		SourceIPs: []string{"205.192.0.0/16", "205.159.0.0/16"},
	}}
	resp, err := s.compute.AuthorizeSecurityGroup(compute.SecurityGroup{Name: "websrv"}, perms)

	req := testServer.WaitRequest()

	c.Assert(req.Form["Action"], DeepEquals, []string{"AuthorizeSecurityGroupIngress"})
	c.Assert(req.Form["GroupName"], DeepEquals, []string{"websrv"})
	c.Assert(req.Form["IpPermissions.1.IpProtocol"], DeepEquals, []string{"tcp"})
	c.Assert(req.Form["IpPermissions.1.FromPort"], DeepEquals, []string{"80"})
	c.Assert(req.Form["IpPermissions.1.ToPort"], DeepEquals, []string{"80"})
	c.Assert(req.Form["IpPermissions.1.IpRanges.1.CidrIp"], DeepEquals, []string{"205.192.0.0/16"})
	c.Assert(req.Form["IpPermissions.1.IpRanges.2.CidrIp"], DeepEquals, []string{"205.159.0.0/16"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
}

func (s *S) TestAuthorizeSecurityGroupExample1WithId(c *C) {
	testServer.Response(200, nil, AuthorizeSecurityGroupIngressExample)

	perms := []compute.IPPerm{{
		Protocol:  "tcp",
		FromPort:  80,
		ToPort:    80,
		SourceIPs: []string{"205.192.0.0/16", "205.159.0.0/16"},
	}}
	// ignore return and error - we're only want to check the parameter handling.
	s.compute.AuthorizeSecurityGroup(compute.SecurityGroup{Id: "sg-67ad940e", Name: "ignored"}, perms)

	req := testServer.WaitRequest()

	c.Assert(req.Form["GroupName"], IsNil)
	c.Assert(req.Form["GroupId"], DeepEquals, []string{"sg-67ad940e"})
}

func (s *S) TestAuthorizeSecurityGroupExample2(c *C) {
	testServer.Response(200, nil, AuthorizeSecurityGroupIngressExample)

	perms := []compute.IPPerm{{
		Protocol: "tcp",
		FromPort: 80,
		ToPort:   81,
		SourceGroups: []compute.UserSecurityGroup{
			{OwnerId: "999988887777", Name: "OtherAccountGroup"},
			{Id: "sg-67ad940e"},
		},
	}}
	resp, err := s.compute.AuthorizeSecurityGroup(compute.SecurityGroup{Name: "websrv"}, perms)

	req := testServer.WaitRequest()

	c.Assert(req.Form["Action"], DeepEquals, []string{"AuthorizeSecurityGroupIngress"})
	c.Assert(req.Form["GroupName"], DeepEquals, []string{"websrv"})
	c.Assert(req.Form["IpPermissions.1.IpProtocol"], DeepEquals, []string{"tcp"})
	c.Assert(req.Form["IpPermissions.1.FromPort"], DeepEquals, []string{"80"})
	c.Assert(req.Form["IpPermissions.1.ToPort"], DeepEquals, []string{"81"})
	c.Assert(req.Form["IpPermissions.1.Groups.1.UserId"], DeepEquals, []string{"999988887777"})
	c.Assert(req.Form["IpPermissions.1.Groups.1.GroupName"], DeepEquals, []string{"OtherAccountGroup"})
	c.Assert(req.Form["IpPermissions.1.Groups.2.UserId"], IsNil)
	c.Assert(req.Form["IpPermissions.1.Groups.2.GroupName"], IsNil)
	c.Assert(req.Form["IpPermissions.1.Groups.2.GroupId"], DeepEquals, []string{"sg-67ad940e"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
}

func (s *S) TestRevokeSecurityGroupExample(c *C) {
	// RevokeSecurityGroup is implemented by the same code as AuthorizeSecurityGroup
	// so there's no need to duplicate all the tests.
	testServer.Response(200, nil, RevokeSecurityGroupIngressExample)

	resp, err := s.compute.RevokeSecurityGroup(compute.SecurityGroup{Name: "websrv"}, nil)

	req := testServer.WaitRequest()

	c.Assert(req.Form["Action"], DeepEquals, []string{"RevokeSecurityGroupIngress"})
	c.Assert(req.Form["GroupName"], DeepEquals, []string{"websrv"})
	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
}

func (s *S) TestStartInstances(c *C) {
	testServer.Response(200, nil, StartInstancesExample)

	resp, err := s.compute.StartInstances("10a64379")
	req := testServer.WaitRequest()

	c.Assert(req.Form["Action"], DeepEquals, []string{"StartInstances"})
	c.Assert(req.Form["InstanceId.1"], DeepEquals, []string{"10a64379"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")

	s0 := resp.StateChanges[0]
	c.Assert(s0.InstanceId, Equals, "10a64379")
	c.Assert(s0.CurrentState.Code, Equals, 0)
	c.Assert(s0.CurrentState.Name, Equals, "pending")
	c.Assert(s0.PreviousState.Code, Equals, 80)
	c.Assert(s0.PreviousState.Name, Equals, "stopped")
}

func (s *S) TestStopInstances(c *C) {
	testServer.Response(200, nil, StopInstancesExample)

	opts := compute.StopInstancesOptions{
		InstanceIds: []string{
			"9145d31f",
		},
	}
	resp, err := s.compute.StopInstances(&opts)
	req := testServer.WaitRequest()

	c.Assert(req.Form["Action"], DeepEquals, []string{"StopInstances"})
	c.Assert(req.Form["InstanceId.1"], DeepEquals, []string{"9145d31f"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")

	s0 := resp.StateChanges[0]
	c.Assert(s0.InstanceId, Equals, "10a64379")
	c.Assert(s0.CurrentState.Code, Equals, 64)
	c.Assert(s0.CurrentState.Name, Equals, "stopping")
	c.Assert(s0.PreviousState.Code, Equals, 16)
	c.Assert(s0.PreviousState.Name, Equals, "running")
}

func (s *S) TestRebootInstances(c *C) {
	testServer.Response(200, nil, RebootInstancesExample)

	opts := compute.RebootInstancesOptions{
		InstanceIds: []string{
			"9145d31f",
		},
	}
	resp, err := s.compute.RebootInstances(&opts)
	req := testServer.WaitRequest()

	c.Assert(req.Form["Action"], DeepEquals, []string{"RebootInstances"})
	c.Assert(req.Form["InstanceId.1"], DeepEquals, []string{"9145d31f"})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
}

func (s *S) TestSignatureWithEndpointPath(c *C) {
	compute.FakeTime(true)
	defer compute.FakeTime(false)

	testServer.Response(200, nil, RebootInstancesExample)

	options := compute.RebootInstancesOptions{
		InstanceIds: []string{
			"9145d31f",
		},
	}

	// https://bugs.launchpad.net/goamz/+bug/1022749
	compute := compute.NewWithClient(s.compute.Auth, niftycloud.Region{ComputeEndpoint: testServer.URL + "/services/Cloud"}, testutil.DefaultClient)

	_, err := compute.RebootInstances(&options)
	c.Assert(err, IsNil)

	req := testServer.WaitRequest()
	c.Assert(req.Form["Signature"], DeepEquals, []string{"dBRWHVHQ27fB8Zv8JsnkAf8gyT0ARQyCfeYKKuHjxP0="})
}

func (s *S) TestModifyInstance(c *C) {
	testServer.Response(200, nil, ModifyInstanceExample)

	options := compute.ModifyInstance{
		InstanceType:          "small",
		DisableAPITermination: true,
		SecurityGroups:        []compute.SecurityGroup{{Id: "g1"}, {Id: "g2"}},
		UserData:              []byte("1234"),
	}

	resp, err := s.compute.ModifyInstance("2ba64342", &options)
	req := testServer.WaitRequest()

	c.Assert(req.Form["Action"], DeepEquals, []string{"ModifyInstanceAttribute"})
	c.Assert(req.Form["InstanceId"], DeepEquals, []string{"2ba64342"})
	c.Assert(req.Form["InstanceType.Value"], DeepEquals, []string{"small"})
	c.Assert(req.Form["DisableApiTermination.Value"], DeepEquals, []string{"true"})
	c.Assert(req.Form["GroupId.1"], DeepEquals, []string{"g1"})
	c.Assert(req.Form["GroupId.2"], DeepEquals, []string{"g2"})
	c.Assert(req.Form["UserData"], DeepEquals, []string{"MTIzNA=="})

	c.Assert(err, IsNil)
	c.Assert(resp.RequestId, Equals, "59dbff89-35bd-4eac-99ed-be587EXAMPLE")
}
