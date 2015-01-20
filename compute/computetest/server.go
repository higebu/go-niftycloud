// The computetest package implements a fake NIFTY Cloud provider with
// the capability of inducing errors on any given operation,
// and retrospectively determining what operations have been
// carried out.
package computetest

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"github.com/higebu/go-niftycloud/compute"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var b64 = base64.StdEncoding

// Action represents a request that changes the compute state.
type Action struct {
	RequestId string

	// Request holds the requested action as a url.Values instance
	Request url.Values

	// If the action succeeded, Response holds the value that
	// was marshalled to build the XML response for the request.
	Response interface{}

	// If the action failed, Err holds an error giving details of the failure.
	Err *compute.Error
}

// TODO possible other things:
// - some virtual time stamp interface, so a client
// can ask for all actions after a certain virtual time.

// Server implements an NIFTY Cloud simulator for use in testing.
type Server struct {
	url      string
	listener net.Listener
	mu       sync.Mutex
	reqs     []*Action

	instances            map[string]*Instance      // id -> instance
	reservations         map[string]*reservation   // id -> reservation
	groups               map[string]*securityGroup // id -> group
	maxId                counter
	reqId                counter
	reservationId        counter
	groupId              counter
	initialInstanceState compute.InstanceState
}

// reservation holds a simulated compute reservation.
type reservation struct {
	id        string
	instances map[string]*Instance
	groups    []*securityGroup
}

// instance holds a simulated compute instance
type Instance struct {
	// UserData holds the data that was passed to the RunInstances request
	// when the instance was started.
	UserData    []byte
	id          string
	imageId     string
	reservation *reservation
	instType    string
	state       compute.InstanceState
}

// permKey represents permission for a given security
// group or IP address (but not both) to access a given range of
// ports. Equality of permKeys is used in the implementation of
// permission sets, relying on the uniqueness of securityGroup
// instances.
type permKey struct {
	protocol string
	fromPort int
	toPort   int
	group    *securityGroup
	ipAddr   string
}

// securityGroup holds a simulated compute security group.
// Instances of securityGroup should only be created through
// Server.createSecurityGroup to ensure that groups can be
// compared by pointer value.
type securityGroup struct {
	id          string
	name        string
	description string

	perms map[permKey]bool
}

func (g *securityGroup) computeSecurityGroup() compute.SecurityGroup {
	return compute.SecurityGroup{
		Name: g.name,
		Id:   g.id,
	}
}

func (g *securityGroup) matchAttr(attr, value string) (ok bool, err error) {
	switch attr {
	case "description":
		return g.description == value, nil
	case "group-id":
		return g.id == value, nil
	case "group-name":
		return g.name == value, nil
	case "ip-permission.cidr":
		return g.hasPerm(func(k permKey) bool { return k.ipAddr == value }), nil
	case "ip-permission.group-name":
		return g.hasPerm(func(k permKey) bool {
			return k.group != nil && k.group.name == value
		}), nil
	case "ip-permission.from-port":
		port, err := strconv.Atoi(value)
		if err != nil {
			return false, err
		}
		return g.hasPerm(func(k permKey) bool { return k.fromPort == port }), nil
	case "ip-permission.to-port":
		port, err := strconv.Atoi(value)
		if err != nil {
			return false, err
		}
		return g.hasPerm(func(k permKey) bool { return k.toPort == port }), nil
	case "ip-permission.protocol":
		return g.hasPerm(func(k permKey) bool { return k.protocol == value }), nil
	case "owner-id":
		return value == ownerId, nil
	}
	return false, fmt.Errorf("unknown attribute %q", attr)
}

func (g *securityGroup) hasPerm(test func(k permKey) bool) bool {
	for k := range g.perms {
		if test(k) {
			return true
		}
	}
	return false
}

// computePerms returns the list of NIFTY Cloud permissions granted
// to g. It groups permissions by port range and protocol.
func (g *securityGroup) computePerms() (perms []compute.IPPerm) {
	// The grouping is held in result. We use permKey for convenience,
	// (ensuring that the group and ipAddr of each key is zero). For
	// each protocol/port range combination, we build up the permission
	// set in the associated value.
	result := make(map[permKey]*compute.IPPerm)
	for k := range g.perms {
		groupKey := k
		groupKey.group = nil
		groupKey.ipAddr = ""

		computep := result[groupKey]
		if computep == nil {
			computep = &compute.IPPerm{
				Protocol: k.protocol,
				FromPort: k.fromPort,
				ToPort:   k.toPort,
			}
			result[groupKey] = computep
		}
		if k.group != nil {
			computep.SourceGroups = append(computep.SourceGroups,
				compute.UserSecurityGroup{
					Id:      k.group.id,
					Name:    k.group.name,
					OwnerId: ownerId,
				})
		} else {
			computep.SourceIPs = append(computep.SourceIPs, k.ipAddr)
		}
	}
	for _, computep := range result {
		perms = append(perms, *computep)
	}
	return
}

var actions = map[string]func(*Server, http.ResponseWriter, *http.Request, string) interface{}{
	"RunInstances":                  (*Server).runInstances,
	"TerminateInstances":            (*Server).terminateInstances,
	"DescribeInstances":             (*Server).describeInstances,
	"CreateSecurityGroup":           (*Server).createSecurityGroup,
	"DescribeSecurityGroups":        (*Server).describeSecurityGroups,
	"DeleteSecurityGroup":           (*Server).deleteSecurityGroup,
	"AuthorizeSecurityGroupIngress": (*Server).authorizeSecurityGroupIngress,
	"RevokeSecurityGroupIngress":    (*Server).revokeSecurityGroupIngress,
}

const ownerId = "9876"

// newAction allocates a new action and adds it to the
// recorded list of server actions.
func (srv *Server) newAction() *Action {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	a := new(Action)
	srv.reqs = append(srv.reqs, a)
	return a
}

// NewServer returns a new server.
func NewServer() (*Server, error) {
	srv := &Server{
		instances:            make(map[string]*Instance),
		groups:               make(map[string]*securityGroup),
		reservations:         make(map[string]*reservation),
		initialInstanceState: Pending,
	}

	// Add default security group.
	g := &securityGroup{
		name:        "default",
		description: "default group",
		id:          fmt.Sprintf("sg-%d", srv.groupId.next()),
	}
	g.perms = map[permKey]bool{
		permKey{
			protocol: "icmp",
			fromPort: -1,
			toPort:   -1,
			group:    g,
		}: true,
		permKey{
			protocol: "tcp",
			fromPort: 0,
			toPort:   65535,
			group:    g,
		}: true,
		permKey{
			protocol: "udp",
			fromPort: 0,
			toPort:   65535,
			group:    g,
		}: true,
	}
	srv.groups[g.id] = g

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("cannot listen on localhost: %v", err)
	}
	srv.listener = l

	srv.url = "http://" + l.Addr().String()

	// we use HandlerFunc rather than *Server directly so that we
	// can avoid exporting HandlerFunc from *Server.
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		srv.serveHTTP(w, req)
	}))
	return srv, nil
}

// Quit closes down the server.
func (srv *Server) Quit() {
	srv.listener.Close()
}

// SetInitialInstanceState sets the state that any new instances will be started in.
func (srv *Server) SetInitialInstanceState(state compute.InstanceState) {
	srv.mu.Lock()
	srv.initialInstanceState = state
	srv.mu.Unlock()
}

// URL returns the URL of the server.
func (srv *Server) URL() string {
	return srv.url
}

// serveHTTP serves the NIFTY Cloud protocol.
func (srv *Server) serveHTTP(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	a := srv.newAction()
	a.RequestId = fmt.Sprintf("req%d", srv.reqId.next())
	a.Request = req.Form

	// Methods on Server that deal with parsing user data
	// may fail. To save on error handling code, we allow these
	// methods to call fatalf, which will panic with an *compute.Error
	// which will be caught here and returned
	// to the client as a properly formed NIFTY Cloud error.
	defer func() {
		switch err := recover().(type) {
		case *compute.Error:
			a.Err = err
			err.RequestId = a.RequestId
			writeError(w, err)
		case nil:
		default:
			panic(err)
		}
	}()

	f := actions[req.Form.Get("Action")]
	if f == nil {
		fatalf(400, "InvalidParameterValue", "Unrecognized Action")
	}

	response := f(srv, w, req, a.RequestId)
	a.Response = response

	w.Header().Set("Content-Type", `xml version="1.0" encoding="UTF-8"`)
	xmlMarshal(w, response)
}

// Instance returns the instance for the given instance id.
// It returns nil if there is no such instance.
func (srv *Server) Instance(id string) *Instance {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.instances[id]
}

// writeError writes an appropriate error response.
// TODO how should we deal with errors when the
// error itself is potentially generated by backend-agnostic
// code?
func writeError(w http.ResponseWriter, err *compute.Error) {
	// Error encapsulates an error returned by NIFTY Cloud.
	// TODO merge with compute.Error when xml supports ignoring a field.
	type computeerror struct {
		Code      string // NIFTY Cloud error code ("UnsupportedOperation", ...)
		Message   string // The human-oriented error message
		RequestId string
	}

	type Response struct {
		RequestId string
		Errors    []computeerror `xml:"Errors>Error"`
	}

	w.Header().Set("Content-Type", `xml version="1.0" encoding="UTF-8"`)
	w.WriteHeader(err.StatusCode)
	xmlMarshal(w, Response{
		RequestId: err.RequestId,
		Errors: []computeerror{{
			Code:    err.Code,
			Message: err.Message,
		}},
	})
}

// xmlMarshal is the same as xml.Marshal except that
// it panics on error. The marshalling should not fail,
// but we want to know if it does.
func xmlMarshal(w io.Writer, x interface{}) {
	if err := xml.NewEncoder(w).Encode(x); err != nil {
		panic(fmt.Errorf("error marshalling %#v: %v", x, err))
	}
}

// formToGroups parses a set of SecurityGroup form values
// as found in a RunInstances request, and returns the resulting
// slice of security groups.
// It calls fatalf if a group is not found.
func (srv *Server) formToGroups(form url.Values) []*securityGroup {
	var groups []*securityGroup
	for name, values := range form {
		switch {
		case strings.HasPrefix(name, "SecurityGroupId."):
			if g := srv.groups[values[0]]; g != nil {
				groups = append(groups, g)
			} else {
				fatalf(400, "InvalidGroup.NotFound", "unknown group id %q", values[0])
			}
		case strings.HasPrefix(name, "SecurityGroup."):
			var found *securityGroup
			for _, g := range srv.groups {
				if g.name == values[0] {
					found = g
				}
			}
			if found == nil {
				fatalf(400, "InvalidGroup.NotFound", "unknown group name %q", values[0])
			}
			groups = append(groups, found)
		}
	}
	return groups
}

// runInstances implements the NIFTY Cloud RunInstances entry point.
func (srv *Server) runInstances(w http.ResponseWriter, req *http.Request, reqId string) interface{} {
	var userData []byte
	if data := req.Form.Get("UserData"); data != "" {
		var err error
		userData, err = b64.DecodeString(data)
		if err != nil {
			fatalf(400, "InvalidParameterValue", "bad UserData value: %v", err)
		}
	}

	// TODO attributes still to consider:
	//    ImageId:                  accept anything, we can verify later
	//    KeyName                   ?
	//    InstanceType              ?
	//    KernelId                  ?
	//    RamdiskId                 ?
	//    AvailabilityZone          ?
	//    GroupName                 tag
	//    Monitoring                ignore?
	//    SubnetId                  ?
	//    DisableAPITermination     bool
	//    ShutdownBehavior          string
	//    PrivateIPAddress          string

	srv.mu.Lock()
	defer srv.mu.Unlock()

	// make sure that form fields are correct before creating the reservation.
	instType := req.Form.Get("InstanceType")
	imageId := req.Form.Get("ImageId")

	r := srv.newReservation(srv.formToGroups(req.Form))

	var resp compute.RunInstancesResp
	resp.RequestId = reqId
	resp.ReservationId = r.id
	resp.OwnerId = ownerId

	inst := srv.newInstance(r, instType, imageId, srv.initialInstanceState)
	inst.UserData = userData
	resp.Instances = append(resp.Instances, inst.computeinstance())
	return &resp
}

func (srv *Server) group(group compute.SecurityGroup) *securityGroup {
	if group.Id != "" {
		return srv.groups[group.Id]
	}
	for _, g := range srv.groups {
		if g.name == group.Name {
			return g
		}
	}
	return nil
}

// NewInstances creates n new instances in srv with the given instance type,
// image ID,  initial state and security groups. If any group does not already
// exist, it will be created. NewInstances returns the ids of the new instances.
func (srv *Server) NewInstances(n int, instType string, imageId string, state compute.InstanceState, groups []compute.SecurityGroup) []string {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	rgroups := make([]*securityGroup, len(groups))
	for i, group := range groups {
		g := srv.group(group)
		if g == nil {
			fatalf(400, "InvalidGroup.NotFound", "no such group %v", g)
		}
		rgroups[i] = g
	}
	r := srv.newReservation(rgroups)

	ids := make([]string, n)
	for i := 0; i < n; i++ {
		inst := srv.newInstance(r, instType, imageId, state)
		ids[i] = inst.id
	}
	return ids
}

func (srv *Server) newInstance(r *reservation, instType string, imageId string, state compute.InstanceState) *Instance {
	inst := &Instance{
		id:          fmt.Sprintf("i-%d", srv.maxId.next()),
		instType:    instType,
		imageId:     imageId,
		state:       state,
		reservation: r,
	}
	srv.instances[inst.id] = inst
	r.instances[inst.id] = inst
	return inst
}

func (srv *Server) newReservation(groups []*securityGroup) *reservation {
	r := &reservation{
		id:        fmt.Sprintf("r-%d", srv.reservationId.next()),
		instances: make(map[string]*Instance),
		groups:    groups,
	}

	srv.reservations[r.id] = r
	return r
}

func (srv *Server) terminateInstances(w http.ResponseWriter, req *http.Request, reqId string) interface{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	var resp compute.TerminateInstancesResp
	resp.RequestId = reqId
	var insts []*Instance
	for attr, vals := range req.Form {
		if strings.HasPrefix(attr, "InstanceId.") {
			id := vals[0]
			inst := srv.instances[id]
			if inst == nil {
				fatalf(400, "InvalidInstanceID.NotFound", "no such instance id %q", id)
			}
			insts = append(insts, inst)
		}
	}
	for _, inst := range insts {
		resp.StateChanges = append(resp.StateChanges, inst.terminate())
	}
	return &resp
}

func (inst *Instance) terminate() (d compute.InstanceStateChange) {
	d.PreviousState = inst.state
	inst.state = ShuttingDown
	d.CurrentState = inst.state
	d.InstanceId = inst.id
	return d
}

func (inst *Instance) computeinstance() compute.Instance {
	return compute.Instance{
		InstanceId:   inst.id,
		InstanceType: inst.instType,
		ImageId:      inst.imageId,
		// TODO the rest
	}
}

func (inst *Instance) matchAttr(attr, value string) (ok bool, err error) {
	switch attr {
	case "architecture":
		return value == "i386", nil
	case "instance-id":
		return inst.id == value, nil
	case "group-id":
		for _, g := range inst.reservation.groups {
			if g.id == value {
				return true, nil
			}
		}
		return false, nil
	case "group-name":
		for _, g := range inst.reservation.groups {
			if g.name == value {
				return true, nil
			}
		}
		return false, nil
	case "image-id":
		return value == inst.imageId, nil
	case "instance-state-code":
		code, err := strconv.Atoi(value)
		if err != nil {
			return false, err
		}
		return code&0xff == inst.state.Code, nil
	case "instance-state-name":
		return value == inst.state.Name, nil
	}
	return false, fmt.Errorf("unknown attribute %q", attr)
}

var (
	Pending      = compute.InstanceState{0, "pending"}
	Running      = compute.InstanceState{16, "running"}
	ShuttingDown = compute.InstanceState{32, "shutting-down"}
	Terminated   = compute.InstanceState{16, "terminated"}
	Stopped      = compute.InstanceState{16, "stopped"}
)

func (srv *Server) createSecurityGroup(w http.ResponseWriter, req *http.Request, reqId string) interface{} {
	name := req.Form.Get("GroupName")
	if name == "" {
		fatalf(400, "InvalidParameterValue", "empty security group name")
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.group(compute.SecurityGroup{Name: name}) != nil {
		fatalf(400, "InvalidGroup.Duplicate", "group %q already exists", name)
	}
	g := &securityGroup{
		name:        name,
		description: req.Form.Get("GroupDescription"),
		id:          fmt.Sprintf("sg-%d", srv.groupId.next()),
		perms:       make(map[permKey]bool),
	}
	srv.groups[g.id] = g
	// we define a local type for this because compute.CreateSecurityGroupResp
	// contains SecurityGroup, but the response to this request
	// should not contain the security group name.
	type CreateSecurityGroupResponse struct {
		RequestId string `xml:"requestId"`
		Return    bool   `xml:"return"`
		GroupId   string `xml:"groupId"`
	}
	r := &CreateSecurityGroupResponse{
		RequestId: reqId,
		Return:    true,
		GroupId:   g.id,
	}
	return r
}

func (srv *Server) notImplemented(w http.ResponseWriter, req *http.Request, reqId string) interface{} {
	fatalf(500, "InternalError", "not implemented")
	panic("not reached")
}

func (srv *Server) describeInstances(w http.ResponseWriter, req *http.Request, reqId string) interface{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	insts := make(map[*Instance]bool)
	for name, vals := range req.Form {
		if !strings.HasPrefix(name, "InstanceId.") {
			continue
		}
		inst := srv.instances[vals[0]]
		if inst == nil {
			fatalf(400, "InvalidInstanceID.NotFound", "instance %q not found", vals[0])
		}
		insts[inst] = true
	}

	f := newFilter(req.Form)

	var resp compute.DescribeInstancesResp
	resp.RequestId = reqId
	for _, r := range srv.reservations {
		var instances []compute.Instance
		for _, inst := range r.instances {
			if len(insts) > 0 && !insts[inst] {
				continue
			}
			ok, err := f.ok(inst)
			if ok {
				instances = append(instances, inst.computeinstance())
			} else if err != nil {
				fatalf(400, "InvalidParameterValue", "describe instances: %v", err)
			}
		}
		if len(instances) > 0 {
			var groups []compute.SecurityGroup
			for _, g := range r.groups {
				groups = append(groups, g.computeSecurityGroup())
			}
			resp.Reservations = append(resp.Reservations, compute.Reservation{
				ReservationId:  r.id,
				OwnerId:        ownerId,
				Instances:      instances,
				SecurityGroups: groups,
			})
		}
	}
	return &resp
}

func (srv *Server) describeSecurityGroups(w http.ResponseWriter, req *http.Request, reqId string) interface{} {
	// BUG similar bug to describeInstances, but for GroupName and GroupId
	srv.mu.Lock()
	defer srv.mu.Unlock()

	var groups []*securityGroup
	for name, vals := range req.Form {
		var g compute.SecurityGroup
		switch {
		case strings.HasPrefix(name, "GroupName."):
			g.Name = vals[0]
		case strings.HasPrefix(name, "GroupId."):
			g.Id = vals[0]
		default:
			continue
		}
		sg := srv.group(g)
		if sg == nil {
			fatalf(400, "InvalidGroup.NotFound", "no such group %v", g)
		}
		groups = append(groups, sg)
	}
	if len(groups) == 0 {
		for _, g := range srv.groups {
			groups = append(groups, g)
		}
	}

	f := newFilter(req.Form)
	var resp compute.SecurityGroupsResp
	resp.RequestId = reqId
	for _, group := range groups {
		ok, err := f.ok(group)
		if ok {
			resp.Groups = append(resp.Groups, compute.SecurityGroupInfo{
				OwnerId:       ownerId,
				SecurityGroup: group.computeSecurityGroup(),
				Description:   group.description,
				IPPerms:       group.computePerms(),
			})
		} else if err != nil {
			fatalf(400, "InvalidParameterValue", "describe security groups: %v", err)
		}
	}
	return &resp
}

func (srv *Server) authorizeSecurityGroupIngress(w http.ResponseWriter, req *http.Request, reqId string) interface{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	g := srv.group(compute.SecurityGroup{
		Name: req.Form.Get("GroupName"),
		Id:   req.Form.Get("GroupId"),
	})
	if g == nil {
		fatalf(400, "InvalidGroup.NotFound", "group not found")
	}
	perms := srv.parsePerms(req)

	for _, p := range perms {
		if g.perms[p] {
			fatalf(400, "InvalidPermission.Duplicate", "Permission has already been authorized on the specified group")
		}
	}
	for _, p := range perms {
		g.perms[p] = true
	}
	return &compute.SimpleResp{
		XMLName:   xml.Name{"", "AuthorizeSecurityGroupIngressResponse"},
		RequestId: reqId,
	}
}

func (srv *Server) revokeSecurityGroupIngress(w http.ResponseWriter, req *http.Request, reqId string) interface{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	g := srv.group(compute.SecurityGroup{
		Name: req.Form.Get("GroupName"),
		Id:   req.Form.Get("GroupId"),
	})
	if g == nil {
		fatalf(400, "InvalidGroup.NotFound", "group not found")
	}
	perms := srv.parsePerms(req)

	// Note NIFTY Cloud does not give an error if asked to revoke an authorization
	// that does not exist.
	for _, p := range perms {
		delete(g.perms, p)
	}
	return &compute.SimpleResp{
		XMLName:   xml.Name{"", "RevokeSecurityGroupIngressResponse"},
		RequestId: reqId,
	}
}

var secGroupPat = regexp.MustCompile(`^sg-[a-z0-9]+$`)
var ipPat = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$`)
var ownerIdPat = regexp.MustCompile(`^[0-9]+$`)

// parsePerms returns a slice of permKey values extracted
// from the permission fields in req.
func (srv *Server) parsePerms(req *http.Request) []permKey {
	// perms maps an index found in the form to its associated
	// IPPerm. For instance, the form value with key
	// "IpPermissions.3.FromPort" will be stored in perms[3].FromPort
	perms := make(map[int]compute.IPPerm)

	type subgroupKey struct {
		id1, id2 int
	}
	// Each IPPerm can have many source security groups.  The form key
	// for a source security group contains two indices: the index
	// of the IPPerm and the sub-index of the security group. The
	// sourceGroups map maps from a subgroupKey containing these
	// two indices to the associated security group. For instance,
	// the form value with key "IPPermissions.3.Groups.2.GroupName"
	// will be stored in sourceGroups[subgroupKey{3, 2}].Name.
	sourceGroups := make(map[subgroupKey]compute.UserSecurityGroup)

	// For each value in the form we store its associated information in the
	// above maps. The maps are necessary because the form keys may
	// arrive in any order, and the indices are not
	// necessarily sequential or even small.
	for name, vals := range req.Form {
		val := vals[0]
		var id1 int
		var rest string
		if x, _ := fmt.Sscanf(name, "IpPermissions.%d.%s", &id1, &rest); x != 2 {
			continue
		}
		computep := perms[id1]
		switch {
		case rest == "FromPort":
			computep.FromPort = atoi(val)
		case rest == "ToPort":
			computep.ToPort = atoi(val)
		case rest == "IpProtocol":
			switch val {
			case "tcp", "udp", "icmp":
				computep.Protocol = val
			default:
				// check it's a well formed number
				atoi(val)
				computep.Protocol = val
			}
		case strings.HasPrefix(rest, "Groups."):
			k := subgroupKey{id1: id1}
			if x, _ := fmt.Sscanf(rest[len("Groups."):], "%d.%s", &k.id2, &rest); x != 2 {
				continue
			}
			g := sourceGroups[k]
			switch rest {
			case "UserId":
				// BUG if the user id is blank, this does not conform to the
				// way that NIFTY Cloud handles it - a specified but blank owner id
				// can cause RevokeSecurityGroupIngress to fail with
				// "group not found" even if the security group id has been
				// correctly specified.
				// By failing here, we ensure that we fail early in this case.
				if !ownerIdPat.MatchString(val) {
					fatalf(400, "InvalidUserID.Malformed", "Invalid user ID: %q", val)
				}
				g.OwnerId = val
			case "GroupName":
				g.Name = val
			case "GroupId":
				if !secGroupPat.MatchString(val) {
					fatalf(400, "InvalidGroupId.Malformed", "Invalid group ID: %q", val)
				}
				g.Id = val
			default:
				fatalf(400, "UnknownParameter", "unknown parameter %q", name)
			}
			sourceGroups[k] = g
		case strings.HasPrefix(rest, "IpRanges."):
			var id2 int
			if x, _ := fmt.Sscanf(rest[len("IpRanges."):], "%d.%s", &id2, &rest); x != 2 {
				continue
			}
			switch rest {
			case "CidrIp":
				if !ipPat.MatchString(val) {
					fatalf(400, "InvalidPermission.Malformed", "Invalid IP range: %q", val)
				}
				computep.SourceIPs = append(computep.SourceIPs, val)
			default:
				fatalf(400, "UnknownParameter", "unknown parameter %q", name)
			}
		default:
			fatalf(400, "UnknownParameter", "unknown parameter %q", name)
		}
		perms[id1] = computep
	}
	// Associate each set of source groups with its IPPerm.
	for k, g := range sourceGroups {
		p := perms[k.id1]
		p.SourceGroups = append(p.SourceGroups, g)
		perms[k.id1] = p
	}

	// Now that we have built up the IPPerms we need, we check for
	// parameter errors and build up a permKey for each permission,
	// looking up security groups from srv as we do so.
	var result []permKey
	for _, p := range perms {
		if p.FromPort > p.ToPort {
			fatalf(400, "InvalidParameterValue", "invalid port range")
		}
		k := permKey{
			protocol: p.Protocol,
			fromPort: p.FromPort,
			toPort:   p.ToPort,
		}
		for _, g := range p.SourceGroups {
			if g.OwnerId != "" && g.OwnerId != ownerId {
				fatalf(400, "InvalidGroup.NotFound", "group %q not found", g.Name)
			}
			var computeg compute.SecurityGroup
			switch {
			case g.Id != "":
				computeg.Id = g.Id
			case g.Name != "":
				computeg.Name = g.Name
			}
			k.group = srv.group(computeg)
			if k.group == nil {
				fatalf(400, "InvalidGroup.NotFound", "group %v not found", g)
			}
			result = append(result, k)
		}
		k.group = nil
		for _, ip := range p.SourceIPs {
			k.ipAddr = ip
			result = append(result, k)
		}
	}
	return result
}

func (srv *Server) deleteSecurityGroup(w http.ResponseWriter, req *http.Request, reqId string) interface{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	g := srv.group(compute.SecurityGroup{
		Name: req.Form.Get("GroupName"),
		Id:   req.Form.Get("GroupId"),
	})
	if g == nil {
		fatalf(400, "InvalidGroup.NotFound", "group not found")
	}
	for _, r := range srv.reservations {
		for _, h := range r.groups {
			if h == g && r.hasRunningMachine() {
				fatalf(500, "InvalidGroup.InUse", "group is currently in use by a running instance")
			}
		}
	}
	for _, sg := range srv.groups {
		// If a group refers to itself, it's ok to delete it.
		if sg == g {
			continue
		}
		for k := range sg.perms {
			if k.group == g {
				fatalf(500, "InvalidGroup.InUse", "group is currently in use by group %q", sg.id)
			}
		}
	}

	delete(srv.groups, g.id)
	return &compute.SimpleResp{
		XMLName:   xml.Name{"", "DeleteSecurityGroupResponse"},
		RequestId: reqId,
	}
}

func (r *reservation) hasRunningMachine() bool {
	for _, inst := range r.instances {
		if inst.state.Code != ShuttingDown.Code && inst.state.Code != Terminated.Code {
			return true
		}
	}
	return false
}

type counter int

func (c *counter) next() (i int) {
	i = int(*c)
	(*c)++
	return
}

// atoi is like strconv.Atoi but is fatal if the
// string is not well formed.
func atoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		fatalf(400, "InvalidParameterValue", "bad number: %v", err)
	}
	return i
}

func fatalf(statusCode int, code string, f string, a ...interface{}) {
	panic(&compute.Error{
		StatusCode: statusCode,
		Code:       code,
		Message:    fmt.Sprintf(f, a...),
	})
}
