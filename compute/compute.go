//
// go-niftycloud - Go packages to interact with the NIFTY Cloud.
//
// Copyright (c) 2014 NIFTY Corp.
//
// Written by Yuya Kusakabe <yuya.kusakabe@gmail.com>
//

package compute

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/higebu/go-niftycloud/niftycloud"
)

const debug = true

// The Compute type encapsulates operations with a specific NIFTY Cloud Compute region.
type Compute struct {
	niftycloud.Auth
	niftycloud.Region
	httpClient *http.Client
	private    byte // Reserve the right of using private data.
}

// NewWithClient creates a new Compute.
func NewWithClient(auth niftycloud.Auth, region niftycloud.Region, client *http.Client) *Compute {
	return &Compute{auth, region, client, 0}
}

// New creates a new NewWithClient.
func New(auth niftycloud.Auth, region niftycloud.Region) *Compute {
	return NewWithClient(auth, region, niftycloud.RetryingClient)
}

// ----------------------------------------------------------------------------
// Filtering helper.

// Filter builds filtering parameters to be used in an NIFTY Cloud Compute query which supports
// filtering.  For example:
//
//     filter := NewFilter()
//     filter.Add("architecture", "i386")
//     filter.Add("launch-index", "0")
//     resp, err := compute.DescribeInstances(nil, filter)
//
type Filter struct {
	m map[string][]string
}

// NewFilter creates a new Filter.
func NewFilter() *Filter {
	return &Filter{make(map[string][]string)}
}

// Add appends a filtering parameter with the given name and value(s).
func (f *Filter) Add(name string, value ...string) {
	f.m[name] = append(f.m[name], value...)
}

func (f *Filter) addParams(params map[string]string) {
	if f != nil {
		a := make([]string, len(f.m))
		i := 0
		for k := range f.m {
			a[i] = k
			i++
		}
		sort.StringSlice(a).Sort()
		for i, k := range a {
			prefix := "Filter." + strconv.Itoa(i+1)
			params[prefix+".Name"] = k
			for j, v := range f.m[k] {
				params[prefix+".Value."+strconv.Itoa(j+1)] = v
			}
		}
	}
}

// ----------------------------------------------------------------------------
// Request dispatching logic.

// Error encapsulates an error returned by NIFTY Cloud.
//
// See http://cloud.nifty.com/api/rest/errorcode.htm for more details.
type Error struct {
	// HTTP status code (200, 403, ...)
	StatusCode int
	// Compute error code ("UnsupportedOperation", ...)
	Code string
	// The human-oriented error message
	Message   string
	RequestId string `xml:"RequestID"`
}

func (err *Error) Error() string {
	if err.Code == "" {
		return err.Message
	}

	return fmt.Sprintf("%s (%s)", err.Message, err.Code)
}

// For now a single error inst is being exposed. In the future it may be useful
// to provide access to all of them, but rather than doing it as an array/slice,
// use a *next pointer, so that it's backward compatible and it continues to be
// easy to handle the first error, which is what most people will want.
type xmlErrors struct {
	RequestId string  `xml:"RequestID"`
	Errors    []Error `xml:"Errors>Error"`
}

var timeNow = time.Now

func (compute *Compute) query(params map[string]string, resp interface{}) error {
	params["Version"] = "2.2"
	params["Timestamp"] = timeNow().In(time.UTC).Format(time.RFC3339)
	endpoint, err := url.Parse(compute.Region.ComputeEndpoint)
	if err != nil {
		return err
	}
	if endpoint.Path == "" {
		endpoint.Path = "/"
	}
	sign(compute.Auth, "GET", endpoint.Path, params, endpoint.Host)
	endpoint.RawQuery = multimap(params).Encode()
	if debug {
		log.Printf("get { %v } -> {\n", endpoint.String())
	}

	r, err := compute.httpClient.Get(endpoint.String())
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if debug {
		dump, _ := httputil.DumpResponse(r, true)
		log.Printf("response:\n")
		log.Printf("%v\n}\n", string(dump))
	}
	if r.StatusCode != 200 {
		return buildError(r)
	}
	err = xml.NewDecoder(r.Body).Decode(resp)
	if err != nil {
		log.Printf("Error while parsing -> %s", err)
	}
	return err
}

func multimap(p map[string]string) url.Values {
	q := make(url.Values, len(p))
	for k, v := range p {
		q[k] = []string{v}
	}
	return q
}

func buildError(r *http.Response) error {
	errors := xmlErrors{}
	xml.NewDecoder(r.Body).Decode(&errors)
	var err Error
	if len(errors.Errors) > 0 {
		err = errors.Errors[0]
	}
	err.RequestId = errors.RequestId
	err.StatusCode = r.StatusCode
	if err.Message == "" {
		err.Message = r.Status
	}
	return &err
}

func makeParams(action string) map[string]string {
	params := make(map[string]string)
	params["Action"] = action
	return params
}

func addParamsList(params map[string]string, label string, ids []string) {
	for i, id := range ids {
		params[label+"."+strconv.Itoa(i+1)] = id
	}
}

func addBlockDeviceParams(prename string, params map[string]string, blockdevices []BlockDeviceMapping) {
	for i, k := range blockdevices {
		// Fixup index since Amazon counts these from 1
		prefix := prename + "BlockDeviceMapping." + strconv.Itoa(i+1) + "."

		if k.DeviceName != "" {
			params[prefix+"DeviceName"] = k.DeviceName
		}

		if k.VirtualName != "" {
			params[prefix+"VirtualName"] = k.VirtualName
		} else if k.NoDevice {
			params[prefix+"NoDevice"] = ""
		} else {
			if k.SnapshotId != "" {
				params[prefix+"Ebs.SnapshotId"] = k.SnapshotId
			}
			if k.VolumeType != "" {
				params[prefix+"Ebs.VolumeType"] = k.VolumeType
			}
			if k.VolumeSize != 0 {
				params[prefix+"Ebs.VolumeSize"] = strconv.FormatInt(k.VolumeSize, 10)
			}
			if k.DeleteOnTermination {
				params[prefix+"Ebs.DeleteOnTermination"] = "true"
			} else {
				params[prefix+"Ebs.DeleteOnTermination"] = "false"
			}
		}
	}
}

// ----------------------------------------------------------------------------
// Instance management functions and types.

// The RunInstancesOptions type encapsulates options for the respective request in NIFTY Cloud.
//
// See http://cloud.nifty.com/api/rest/RunInstances.htm for more details.
type RunInstancesOptions struct {
	ImageId               string
	KeyName               string
	InstanceType          string
	SecurityGroups        []SecurityGroup
	UserData              []byte
	AvailZone             string
	DisableAPITermination bool
	AccountingType        string
	InstanceId            string
	Admin                 string
	Password              string
	IpType                string
	PublicIp              string
	Agreement             string
}

// Response to a RunInstances request.
//
// See http://cloud.nifty.com/api/rest/RunInstances.htm for more details.
type RunInstancesResp struct {
	RequestId      string          `xml:"requestId"`
	ReservationId  string          `xml:"reservationId"`
	OwnerId        string          `xml:"ownerId"`
	SecurityGroups []SecurityGroup `xml:"groupSet>item"`
	Instances      []Instance      `xml:"instancesSet>item"`
}

// BlockDevice represents the association of a block device with an instance.
type BlockDevice struct {
	DeviceName          string `xml:"deviceName"`
	VolumeId            string `xml:"ebs>volumeId"`
	Status              string `xml:"ebs>status"`
	AttachTime          string `xml:"ebs>attachTime"`
	DeleteOnTermination bool   `xml:"ebs>deleteOnTermination"`
}

// Instance encapsulates a running instance in NIFTY Cloud.
//
// See http://cloud.nifty.com/api/rest/DescribeInstances.htm for more details.
type Instance struct {
	InstanceId              string        `xml:"instanceId"`
	InstanceType            string        `xml:"instanceType"`
	ImageId                 string        `xml:"imageId"`
	KeyName                 string        `xml:"keyName"`
	Monitoring              string        `xml:"monitoring>state"`
	AvailZone               string        `xml:"placement>availabilityZone"`
	State                   InstanceState `xml:"instanceState"`
	PrivateIpAddress        string        `xml:"privateIpAddress"`
	PrivateIpAddressV6      string        `xml:"privateIpAddressV6"`
	PublicIpAddress         string        `xml:"ipAddress"`
	PublicIpAddressV6       string        `xml:"ipAddressV6"`
	Architecture            string        `xml:"architecture"`
	LaunchTime              time.Time     `xml:"launchTime"`
	BlockDevices            []BlockDevice `xml:"blockDeviceMapping>item"`
	Description             string        `xml:"description"`
	AccountingType          string        `xml:"accountingType"`
	NextMonthAccountingType string        `xml:"nextMonthAccountingType"`
	InstanceUniqueId        string        `xml:"instanceUniqueId"`
}

// RunInstances starts new instances in NIFTY Cloud.
//
// See http://cloud.nifty.com/api/rest/RunInstances.htm for more details.
func (compute *Compute) RunInstances(options *RunInstancesOptions) (resp *RunInstancesResp, err error) {
	params := makeParams("RunInstances")

	params["ImageId"] = options.ImageId

	params["InstanceType"] = options.InstanceType

	token, err := clientToken()
	if err != nil {
		return nil, err
	}
	params["ClientToken"] = token

	if options.KeyName != "" {
		params["KeyName"] = options.KeyName
	}

	if options.UserData != nil {
		userData := make([]byte, b64.EncodedLen(len(options.UserData)))
		b64.Encode(userData, options.UserData)
		params["UserData"] = string(userData)
	}

	if options.AvailZone != "" {
		params["Placement.AvailabilityZone"] = options.AvailZone
	}

	if options.DisableAPITermination {
		params["DisableApiTermination"] = "true"
	}

	i, j := 1, 1
	for _, g := range options.SecurityGroups {
		if g.Id != "" {
			params["SecurityGroupId."+strconv.Itoa(i)] = g.Id
			i++
		} else {
			params["SecurityGroup."+strconv.Itoa(j)] = g.Name
			j++
		}
	}

	if options.AccountingType != "" {
		params["AccountingType"] = options.AccountingType
	}

	if options.InstanceId != "" {
		params["InstanceId"] = options.InstanceId
	}

	if options.Admin != "" {
		params["Admin"] = options.Admin
	}

	if options.Password != "" {
		params["Password"] = options.Password
	}

	if options.IpType != "" {
		params["IpType"] = options.IpType
	}

	if options.PublicIp != "" {
		params["PublicIp"] = options.PublicIp
	}

	if options.Agreement != "" {
		params["Agreement"] = options.Agreement
	}

	resp = &RunInstancesResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return
}

func clientToken() (string, error) {
	// Maximum Compute client token size is 64 bytes.
	// Each byte expands to two when hex encoded.
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Response to a TerminateInstances request.
//
// See http://cloud.nifty.com/api/rest/TerminateInstances.htm for more details.
type TerminateInstancesResp struct {
	RequestId    string                `xml:"requestId"`
	StateChanges []InstanceStateChange `xml:"instancesSet>item"`
}

// InstanceState encapsulates the state of an instance in NIFTY Cloud.
//
// See http://cloud.nifty.com/api/rest/DescribeInstances.htm for more details.
type InstanceState struct {
	Code int    `xml:"code"` // Watch out, bits 15-8 have unpublished meaning.
	Name string `xml:"name"`
}

// InstanceStateChange informs of the previous and current states
// for an instance when a state change is requested.
type InstanceStateChange struct {
	InstanceId    string        `xml:"instanceId"`
	CurrentState  InstanceState `xml:"currentState"`
	PreviousState InstanceState `xml:"previousState"`
}

// TerminateInstances requests the termination of instances when the given ids.
//
// See http://cloud.nifty.com/api/rest/TerminateInstances.htm for more details.
func (compute *Compute) TerminateInstances(instIds []string) (resp *TerminateInstancesResp, err error) {
	params := makeParams("TerminateInstances")
	addParamsList(params, "InstanceId", instIds)
	resp = &TerminateInstancesResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return
}

// Response to a DescribeInstances request.
//
// See http://cloud.nifty.com/api/rest/DescribeInstances.htm for more details.
type DescribeInstancesResp struct {
	RequestId    string        `xml:"requestId"`
	Reservations []Reservation `xml:"reservationSet>item"`
}

// Reservation represents details about a reservation in NIFTY Cloud.
//
// See http://cloud.nifty.com/api/rest/DescribeInstances.htm for more details.
type Reservation struct {
	ReservationId  string          `xml:"reservationId"`
	OwnerId        string          `xml:"ownerId"`
	RequesterId    string          `xml:"requesterId"`
	SecurityGroups []SecurityGroup `xml:"groupSet>item"`
	Instances      []Instance      `xml:"instancesSet>item"`
}

// Instances returns details about instances in NIFTY Cloud.  Both parameters
// are optional, and if provided will limit the instances returned to those
// matching the given instance ids or filtering rules.
//
// See http://cloud.nifty.com/api/rest/DescribeInstances.htm for more details.
func (compute *Compute) DescribeInstances(instIds []string, filter *Filter) (resp *DescribeInstancesResp, err error) {
	params := makeParams("DescribeInstances")
	addParamsList(params, "InstanceId", instIds)
	filter.addParams(params)
	resp = &DescribeInstancesResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return
}

// ----------------------------------------------------------------------------
// Volume management

// The CreateVolume request parameters
//
// See http://cloud.nifty.com/api/rest/CreateVolume.htm
type CreateVolume struct {
	AvailZone      string
	Size           int64
	SnapshotId     string
	VolumeId       string
	DiskType       string
	InstanceId     string
	AccountingType string
}

// Response to an AttachVolume request
type AttachVolumeResp struct {
	RequestId  string `xml:"requestId"`
	VolumeId   string `xml:"volumeId"`
	InstanceId string `xml:"instanceId"`
	Device     string `xml:"device"`
	Status     string `xml:"status"`
	AttachTime string `xml:"attachTime"`
}

// Response to a CreateVolume request
type CreateVolumeResp struct {
	RequestId      string `xml:"requestId"`
	VolumeId       string `xml:"volumeId"`
	Size           int64  `xml:"size"`
	SnapshotId     string `xml:"snapshotId"`
	AvailZone      string `xml:"availabilityZone"`
	Status         string `xml:"status"`
	CreateTime     string `xml:"createTime"`
	DiskType       string `xml:"diskType"`
	AccountingType string `xml:"accountingType"`
}

// Volume is a single volume.
type Volume struct {
	VolumeId    string             `xml:"volumeId"`
	Size        string             `xml:"size"`
	SnapshotId  string             `xml:"snapshotId"`
	AvailZone   string             `xml:"availabilityZone"`
	Status      string             `xml:"status"`
	Attachments []VolumeAttachment `xml:"attachmentSet>item"`
	DiskType    string             `xml:"diskType"`
}

type VolumeAttachment struct {
	VolumeId   string `xml:"volumeId"`
	InstanceId string `xml:"instanceId"`
	Device     string `xml:"device"`
	Status     string `xml:"status"`
}

// Response to a DescribeVolumes request
type VolumesResp struct {
	RequestId string   `xml:"requestId"`
	Volumes   []Volume `xml:"volumeSet>item"`
}

// Attach a volume.
func (compute *Compute) AttachVolume(volumeId string, instanceId string, device string) (resp *AttachVolumeResp, err error) {
	params := makeParams("AttachVolume")
	params["VolumeId"] = volumeId
	params["InstanceId"] = instanceId
	params["Device"] = device

	resp = &AttachVolumeResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}

	return
}

// Create a new volume.
func (compute *Compute) CreateVolume(options *CreateVolume) (resp *CreateVolumeResp, err error) {
	params := makeParams("CreateVolume")
	params["AvailabilityZone"] = options.AvailZone
	if options.Size > 0 {
		params["Size"] = strconv.FormatInt(options.Size, 10)
	}

	if options.SnapshotId != "" {
		params["SnapshotId"] = options.SnapshotId
	}

	if options.DiskType != "" {
		params["DiskType"] = options.DiskType
	}

	resp = &CreateVolumeResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}

	return
}

// Delete an volume.
func (compute *Compute) DeleteVolume(id string) (resp *SimpleResp, err error) {
	params := makeParams("DeleteVolume")
	params["VolumeId"] = id

	resp = &SimpleResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return
}

// Detaches an volume.
func (compute *Compute) DetachVolume(id string) (resp *SimpleResp, err error) {
	params := makeParams("DetachVolume")
	params["VolumeId"] = id

	resp = &SimpleResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return
}

// Finds or lists all volumes.
func (compute *Compute) Volumes(volIds []string, filter *Filter) (resp *VolumesResp, err error) {
	params := makeParams("DescribeVolumes")
	addParamsList(params, "VolumeId", volIds)
	filter.addParams(params)
	resp = &VolumesResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return
}

// ----------------------------------------------------------------------------
// Availability zone management functions and types.
// See http://cloud.nifty.com/api/rest/DescribeAvailabilityZones.htm for more details.

// DescribeAvailabilityZonesResp represents a response to a DescribeAvailabilityZones
// request in NIFTY Cloud.
type DescribeAvailabilityZonesResp struct {
	RequestId string                 `xml:"requestId"`
	Zones     []AvailabilityZoneInfo `xml:"availabilityZoneInfo>item"`
}

// AvailabilityZoneInfo encapsulates details for an availability zone in NIFTY Cloud.
type AvailabilityZoneInfo struct {
	AvailabilityZone
	State      string   `xml:"zoneState"`
	MessageSet []string `xml:"messageSet>item"`
}

// AvailabilityZone represents an NIFTY Cloud Compute availability zone.
type AvailabilityZone struct {
	Name   string `xml:"zoneName"`
	Region string `xml:"regionName"`
}

// DescribeAvailabilityZones returns details about availability zones in NIFTY Cloud.
// The filter parameter is optional, and if provided will limit the
// availability zones returned to those matching the given filtering
// rules.
//
// See http://cloud.nifty.com/api/rest/DescribeAvailabilityZones.htm for more details.
func (compute *Compute) DescribeAvailabilityZones(filter *Filter) (resp *DescribeAvailabilityZonesResp, err error) {
	params := makeParams("DescribeAvailabilityZones")
	filter.addParams(params)
	resp = &DescribeAvailabilityZonesResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return
}

// ----------------------------------------------------------------------------
// ElasticIp management

// The AllocateAddress request parameters
//
// See http://cloud.nifty.com/api/rest/AllocateAddress.htm
type AllocateAddress struct {
	Domain string
}

// Response to an AllocateAddress request
type AllocateAddressResp struct {
	RequestId    string `xml:"requestId"`
	PublicIp     string `xml:"publicIp"`
	Domain       string `xml:"domain"`
	AllocationId string `xml:"allocationId"`
}

// The AssociateAddress request parameters
//
// See http://cloud.nifty.com/api/rest/AssociateAddress.htm
type AssociateAddress struct {
	InstanceId         string
	PublicIp           string
	AllocationId       string
	AllowReassociation bool
}

// Response to an AssociateAddress request
type AssociateAddressResp struct {
	RequestId     string `xml:"requestId"`
	Return        bool   `xml:"return"`
	AssociationId string `xml:"associationId"`
}

// Address represents an Elastic IP Address
// See http://cloud.nifty.com/api/rest/AllocateAddress.htm for more details
type Address struct {
	PublicIp                string `xml:"publicIp"`
	AllocationId            string `xml:"allocationId"`
	Domain                  string `xml:"domain"`
	InstanceId              string `xml:"instanceId"`
	AssociationId           string `xml:"associationId"`
	NetworkInterfaceId      string `xml:"networkInterfaceId"`
	NetworkInterfaceOwnerId string `xml:"networkInterfaceOwnerId"`
	PrivateIpAddress        string `xml:"privateIpAddress"`
}

type DescribeAddressesResp struct {
	RequestId string    `xml:"requestId"`
	Addresses []Address `xml:"addressesSet>item"`
}

// Allocate a new Elastic IP.
func (compute *Compute) AllocateAddress(options *AllocateAddress) (resp *AllocateAddressResp, err error) {
	params := makeParams("AllocateAddress")
	params["Domain"] = options.Domain

	resp = &AllocateAddressResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}

	return
}

// Release an Elastic IP
func (compute *Compute) ReleasePublicAddress(publicIp string) (resp *SimpleResp, err error) {
	params := makeParams("ReleaseAddress")
	params["PublicIp"] = publicIp

	resp = &SimpleResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}

	return
}

// Associate an address with a instance.
func (compute *Compute) AssociateAddress(options *AssociateAddress) (resp *AssociateAddressResp, err error) {
	params := makeParams("AssociateAddress")
	params["InstanceId"] = options.InstanceId
	if options.PublicIp != "" {
		params["PublicIp"] = options.PublicIp
	}
	if options.AllocationId != "" {
		params["AllocationId"] = options.AllocationId
	}
	if options.AllowReassociation {
		params["AllowReassociation"] = "true"
	}

	resp = &AssociateAddressResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}

	return
}

// Disassociate an address from a instance.
func (compute *Compute) DisassociateAddress(id string) (resp *SimpleResp, err error) {
	params := makeParams("DisassociateAddress")
	params["AssociationId"] = id

	resp = &SimpleResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}

	return
}

// Disassociate an address from a instance.
func (compute *Compute) DisassociateAddressClassic(ip string) (resp *SimpleResp, err error) {
	params := makeParams("DisassociateAddress")
	params["PublicIp"] = ip

	resp = &SimpleResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}

	return
}

// DescribeAddresses returns details about one or more
// Elastic IP Addresses. Returned addresses can be
// filtered by Public IP, Allocation ID or multiple filters
//
// See http://cloud.nifty.com/api/rest/DescribeAddresses.htm for more details.
func (compute *Compute) Addresses(publicIps []string, allocationIds []string, filter *Filter) (resp *DescribeAddressesResp, err error) {
	params := makeParams("DescribeAddresses")
	addParamsList(params, "PublicIp", publicIps)
	addParamsList(params, "AllocationId", allocationIds)
	filter.addParams(params)
	resp = &DescribeAddressesResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return
}

// ----------------------------------------------------------------------------
// Image management functions and types.

// The CreateImage request parameters.
//
// See http://cloud.nifty.com/api/rest/CreateImage.htm for more details.
type CreateImage struct {
	InstanceId   string
	Name         string
	Description  string
	NoReboot     bool
	BlockDevices []BlockDeviceMapping
}

// Response to a CreateImage request.
//
// See http://cloud.nifty.com/api/rest/CreateImage.htm for more details.
type CreateImageResp struct {
	RequestId string `xml:"requestId"`
	ImageId   string `xml:"imageId"`
}

// Response to a DescribeImages request.
//
// See http://cloud.nifty.com/api/rest/DescribeImages.htm for more details.
type ImagesResp struct {
	RequestId string  `xml:"requestId"`
	Images    []Image `xml:"imagesSet>item"`
}

// BlockDeviceMapping represents the association of a block device with an image.
//
// See http://cloud.nifty.com/api/rest/DescribeInstances.htm for more details.
type BlockDeviceMapping struct {
	DeviceName          string `xml:"deviceName"`
	VirtualName         string `xml:"virtualName"`
	SnapshotId          string `xml:"ebs>snapshotId"`
	VolumeType          string `xml:"ebs>volumeType"`
	VolumeSize          int64  `xml:"ebs>volumeSize"`
	DeleteOnTermination bool   `xml:"ebs>deleteOnTermination"`
	NoDevice            bool   `xml:"noDevice"`
}

// Image represents details about an image.
//
// See http://cloud.nifty.com/api/rest/CreateImage.htm for more details.
type Image struct {
	Id                 string               `xml:"imageId"`
	Name               string               `xml:"name"`
	Description        string               `xml:"description"`
	Type               string               `xml:"imageType"`
	State              string               `xml:"imageState"`
	Location           string               `xml:"imageLocation"`
	Public             bool                 `xml:"isPublic"`
	Architecture       string               `xml:"architecture"`
	Platform           string               `xml:"platform"`
	ProductCodes       []string             `xml:"productCode>item>productCode"`
	KernelId           string               `xml:"kernelId"`
	RamdiskId          string               `xml:"ramdiskId"`
	StateReason        string               `xml:"stateReason"`
	OwnerId            string               `xml:"imageOwnerId"`
	OwnerAlias         string               `xml:"imageOwnerAlias"`
	RootDeviceType     string               `xml:"rootDeviceType"`
	RootDeviceName     string               `xml:"rootDeviceName"`
	VirtualizationType string               `xml:"virtualizationType"`
	Hypervisor         string               `xml:"hypervisor"`
	BlockDevices       []BlockDeviceMapping `xml:"blockDeviceMapping>item"`
}

// The ModifyImageAttribute request parameters.
type ModifyImageAttribute struct {
	AddUsers     []string
	RemoveUsers  []string
	AddGroups    []string
	RemoveGroups []string
	ProductCodes []string
	Description  string
}

// The NiftyAssociateImage request parameters.
type NiftyAssociateImage struct {
	ImageId         string
	IsPublic        bool
	IsRedistribute  bool
	DistributionIds []string
}

type NiftyAssociateImageResp struct {
	RequestId string `xml:"requestId"`
	Return    string `xml:"return"`
}

// Creates an image from an instance that is either running or stopped.
//
// See http://cloud.nifty.com/api/rest/CreateImage.htm for more details.
func (compute *Compute) CreateImage(options *CreateImage) (resp *CreateImageResp, err error) {
	params := makeParams("CreateImage")
	params["InstanceId"] = options.InstanceId
	params["Name"] = options.Name
	if options.Description != "" {
		params["Description"] = options.Description
	}
	if options.NoReboot {
		params["NoReboot"] = "true"
	}
	addBlockDeviceParams("", params, options.BlockDevices)

	resp = &CreateImageResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}

	return
}

// Images returns details about available images.
// The ids and filter parameters, if provided, will limit the images returned.
// For example, to get all the private images associated with this account set
// the boolean filter "is-public" to 0.
// For list of filters: {url}
//
// Note: calling this function with nil ids and filter parameters will result in
// a very large number of images being returned.
//
// See http://cloud.nifty.com/api/rest/DescribeImages.htm for more details.
func (compute *Compute) Images(ids []string, filter *Filter) (resp *ImagesResp, err error) {
	params := makeParams("DescribeImages")
	for i, id := range ids {
		params["ImageId."+strconv.Itoa(i+1)] = id
	}
	filter.addParams(params)

	resp = &ImagesResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return
}

// ImagesByOwners returns details about available images.
// The ids, owners, and filter parameters, if provided, will limit the images returned.
// For example, to get all the private images associated with this account set
// the boolean filter "is-public" to 0.
// For list of filters: {url}
//
// Note: calling this function with nil ids and filter parameters will result in
// a very large number of images being returned.
//
// See http://cloud.nifty.com/api/rest/DescribeImages.htm for more details.
func (compute *Compute) ImagesByOwners(ids []string, owners []string, filter *Filter) (resp *ImagesResp, err error) {
	params := makeParams("DescribeImages")
	for i, id := range ids {
		params["ImageId."+strconv.Itoa(i+1)] = id
	}
	for i, owner := range owners {
		params[fmt.Sprintf("Owner.%d", i+1)] = owner
	}

	filter.addParams(params)

	resp = &ImagesResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return
}

// ModifyImageAttribute sets attributes for an image.
//
// See http://cloud.nifty.com/api/rest/ModifyImageAttribute.htm for more details.
func (compute *Compute) ModifyImageAttribute(imageId string, options *ModifyImageAttribute) (resp *SimpleResp, err error) {
	params := makeParams("ModifyImageAttribute")
	params["ImageId"] = imageId
	if options.Description != "" {
		params["Description.Value"] = options.Description
	}

	if options.AddUsers != nil {
		for i, user := range options.AddUsers {
			p := fmt.Sprintf("LaunchPermission.Add.%d.UserId", i+1)
			params[p] = user
		}
	}

	if options.RemoveUsers != nil {
		for i, user := range options.RemoveUsers {
			p := fmt.Sprintf("LaunchPermission.Remove.%d.UserId", i+1)
			params[p] = user
		}
	}

	if options.AddGroups != nil {
		for i, group := range options.AddGroups {
			p := fmt.Sprintf("LaunchPermission.Add.%d.Group", i+1)
			params[p] = group
		}
	}

	if options.RemoveGroups != nil {
		for i, group := range options.RemoveGroups {
			p := fmt.Sprintf("LaunchPermission.Remove.%d.Group", i+1)
			params[p] = group
		}
	}

	if options.ProductCodes != nil {
		addParamsList(params, "ProductCode", options.ProductCodes)
	}

	resp = &SimpleResp{}
	err = compute.query(params, resp)
	if err != nil {
		resp = nil
	}

	return
}

// NiftyAssociateImage associate images.
//
// See http://cloud.nifty.com/api/rest/NiftyAssociateImage.htm for more details.
func (compute *Compute) NiftyAssociateImage(options *NiftyAssociateImage) (resp *NiftyAssociateImageResp, err error) {
	params := makeParams("NiftyAssociateImage")
	params["ImageId"] = options.ImageId
	if options.IsPublic {
		params["IsPublic"] = "true"
	} else {
		params["IsPublic"] = "false"
	}
	if options.IsRedistribute {
		params["IsRedistribute"] = "true"
	}
	if len(options.DistributionIds) > 0 {
		addParamsList(params, "DistributionId", options.DistributionIds)
	}

	resp = &NiftyAssociateImageResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}

	return
}

// ----------------------------------------------------------------------------
// KeyPair management functions and types.

type KeyPair struct {
	Name        string `xml:"keyName"`
	Fingerprint string `xml:"keyFingerprint"`
}

type KeyPairsResp struct {
	RequestId string    `xml:"requestId"`
	Keys      []KeyPair `xml:"keySet>item"`
}

type CreateKeyPairResp struct {
	RequestId      string `xml:"requestId"`
	KeyName        string `xml:"keyName"`
	KeyFingerprint string `xml:"keyFingerprint"`
	KeyMaterial    string `xml:"keyMaterial"`
}

// CreateKeyPair creates a new key pair and returns the private key contents.
//
// See http://cloud.nifty.com/api/rest/CreateKeyPair.htm
func (compute *Compute) CreateKeyPair(keyName string) (resp *CreateKeyPairResp, err error) {
	params := makeParams("CreateKeyPair")
	params["KeyName"] = keyName

	resp = &CreateKeyPairResp{}
	err = compute.query(params, resp)
	if err == nil {
		resp.KeyFingerprint = strings.TrimSpace(resp.KeyFingerprint)
	}
	return
}

// DeleteKeyPair deletes a key pair.
//
// See http://cloud.nifty.com/api/rest/DeleteKeyPair.htm
func (compute *Compute) DeleteKeyPair(name string) (resp *SimpleResp, err error) {
	params := makeParams("DeleteKeyPair")
	params["KeyName"] = name

	resp = &SimpleResp{}
	err = compute.query(params, resp)
	return
}

// KeyPairs returns list of key pairs for this account
//
// See http://cloud.nifty.com/api/rest/DescribeKeyPairs.htm
func (compute *Compute) KeyPairs(keynames []string, filter *Filter) (resp *KeyPairsResp, err error) {
	params := makeParams("DescribeKeyPairs")
	for i, name := range keynames {
		params["KeyName."+strconv.Itoa(i)] = name
	}
	filter.addParams(params)

	resp = &KeyPairsResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// ----------------------------------------------------------------------------
// Security group management functions and types.

// SimpleResp represents a response to an NIFTY Cloud Compute request which on success will
// return no other information besides a request id.
type SimpleResp struct {
	XMLName   xml.Name
	RequestId string `xml:"requestId"`
}

// CreateSecurityGroupResp represents a response to a CreateSecurityGroup request.
type CreateSecurityGroupResp struct {
	SecurityGroup
	RequestId string `xml:"requestId"`
}

// CreateSecurityGroup run a CreateSecurityGroup request in NIFTY Cloud Compute, with the provided
// name and description.
//
// See http://cloud.nifty.com/api/rest/CreateSecurityGroup.htm for more details.
func (compute *Compute) CreateSecurityGroup(group SecurityGroup) (resp *CreateSecurityGroupResp, err error) {
	params := makeParams("CreateSecurityGroup")
	params["GroupName"] = group.Name
	params["GroupDescription"] = group.Description

	resp = &CreateSecurityGroupResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	resp.Name = group.Name
	return resp, nil
}

// SecurityGroupsResp represents a response to a DescribeSecurityGroups
// request in NIFTY Cloud.
//
// See http://cloud.nifty.com/api/rest/DescribeSecurityGroups.htm for more details.
type SecurityGroupsResp struct {
	RequestId string              `xml:"requestId"`
	Groups    []SecurityGroupInfo `xml:"securityGroupInfo>item"`
}

// SecurityGroup encapsulates details for a security group in NIFTY Cloud.
//
// See http://cloud.nifty.com/api/rest/DescribeSecurityGroups.htm for more details.
type SecurityGroupInfo struct {
	SecurityGroup
	OwnerId     string   `xml:"ownerId"`
	Description string   `xml:"groupDescription"`
	IPPerms     []IPPerm `xml:"ipPermissions>item"`
}

// IPPerm represents an allowance within an NIFTY Cloud Compute security group.
//
// See http://cloud.nifty.com/api/rest/AuthorizeSecurityGroupIngress.htm for more details.
type IPPerm struct {
	Protocol     string              `xml:"ipProtocol"`
	FromPort     int                 `xml:"fromPort"`
	ToPort       int                 `xml:"toPort"`
	SourceIPs    []string            `xml:"ipRanges>item>cidrIp"`
	SourceGroups []UserSecurityGroup `xml:"groups>item"`
}

// UserSecurityGroup holds a security group and the owner
// of that group.
type UserSecurityGroup struct {
	Id      string `xml:"groupId"`
	Name    string `xml:"groupName"`
	OwnerId string `xml:"userId"`
}

// SecurityGroup represents an NIFTY Cloud Compute security group.
// If SecurityGroup is used as a parameter, then one of Id or Name
// may be empty. If both are set, then Id is used.
type SecurityGroup struct {
	Id          string `xml:"groupId"`
	Name        string `xml:"groupName"`
	Description string `xml:"groupDescription"`
}

// SecurityGroupNames is a convenience function that
// returns a slice of security groups with the given names.
func SecurityGroupNames(names ...string) []SecurityGroup {
	g := make([]SecurityGroup, len(names))
	for i, name := range names {
		g[i] = SecurityGroup{Name: name}
	}
	return g
}

// SecurityGroupNames is a convenience function that
// returns a slice of security groups with the given ids.
func SecurityGroupIds(ids ...string) []SecurityGroup {
	g := make([]SecurityGroup, len(ids))
	for i, id := range ids {
		g[i] = SecurityGroup{Id: id}
	}
	return g
}

// SecurityGroups returns details about security groups in NIFTY Cloud.  Both parameters
// are optional, and if provided will limit the security groups returned to those
// matching the given groups or filtering rules.
//
// See http://cloud.nifty.com/api/rest/DescribeSecurityGroups.htm for more details.
func (compute *Compute) SecurityGroups(groups []SecurityGroup, filter *Filter) (resp *SecurityGroupsResp, err error) {
	params := makeParams("DescribeSecurityGroups")
	i, j := 1, 1
	for _, g := range groups {
		if g.Id != "" {
			params["GroupId."+strconv.Itoa(i)] = g.Id
			i++
		} else {
			params["GroupName."+strconv.Itoa(j)] = g.Name
			j++
		}
	}
	filter.addParams(params)

	resp = &SecurityGroupsResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteSecurityGroup removes the given security group in NIFTY Cloud.
//
// See http://cloud.nifty.com/api/rest/DeleteSecurityGroup.htm for more details.
func (compute *Compute) DeleteSecurityGroup(group SecurityGroup) (resp *SimpleResp, err error) {
	params := makeParams("DeleteSecurityGroup")
	if group.Id != "" {
		params["GroupId"] = group.Id
	} else {
		params["GroupName"] = group.Name
	}

	resp = &SimpleResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// AuthorizeSecurityGroup creates an allowance for clients matching the provided
// rules to access instances within the given security group.
//
// See http://cloud.nifty.com/api/rest/AuthorizeSecurityGroupIngress.htm for more details.
func (compute *Compute) AuthorizeSecurityGroup(group SecurityGroup, perms []IPPerm) (resp *SimpleResp, err error) {
	return compute.authOrRevoke("AuthorizeSecurityGroupIngress", group, perms)
}

// RevokeSecurityGroup revokes permissions from a group.
//
// See http://cloud.nifty.com/api/rest/RevokeSecurityGroupIngress.htm for more details.
func (compute *Compute) RevokeSecurityGroup(group SecurityGroup, perms []IPPerm) (resp *SimpleResp, err error) {
	return compute.authOrRevoke("RevokeSecurityGroupIngress", group, perms)
}

func (compute *Compute) authOrRevoke(op string, group SecurityGroup, perms []IPPerm) (resp *SimpleResp, err error) {
	params := makeParams(op)
	if group.Id != "" {
		params["GroupId"] = group.Id
	} else {
		params["GroupName"] = group.Name
	}

	for i, perm := range perms {
		prefix := "IpPermissions." + strconv.Itoa(i+1)
		params[prefix+".IpProtocol"] = perm.Protocol
		params[prefix+".FromPort"] = strconv.Itoa(perm.FromPort)
		params[prefix+".ToPort"] = strconv.Itoa(perm.ToPort)
		for j, ip := range perm.SourceIPs {
			params[prefix+".IpRanges."+strconv.Itoa(j+1)+".CidrIp"] = ip
		}
		for j, g := range perm.SourceGroups {
			subprefix := prefix + ".Groups." + strconv.Itoa(j+1)
			if g.OwnerId != "" {
				params[subprefix+".UserId"] = g.OwnerId
			}
			if g.Id != "" {
				params[subprefix+".GroupId"] = g.Id
			} else {
				params[subprefix+".GroupName"] = g.Name
			}
		}
	}

	resp = &SimpleResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// The StopInstances type encapsulates options for the respective request in NIFTY Cloud.
//
// See http://cloud.nifty.com/api/rest/StopInstances.htm for more details.
type StopInstancesOptions struct {
	InstanceIds []string
	Force       bool
}

// The RebootInstancesOptions type encapsulates options for the respective request in NIFTY Cloud.
//
// See http://cloud.nifty.com/api/rest/RebootInstances.htm for more details.
type RebootInstancesOptions struct {
	InstanceIds []string
	Force       bool
}

// Response to a StartInstances request.
//
// See http://cloud.nifty.com/api/rest/StartInstances.htm for more details.
type StartInstanceResp struct {
	RequestId    string                `xml:"requestId"`
	StateChanges []InstanceStateChange `xml:"instancesSet>item"`
}

// Response to a StopInstances request.
//
// See http://cloud.nifty.com/api/rest/StopInstances.htm for more details.
type StopInstanceResp struct {
	RequestId    string                `xml:"requestId"`
	StateChanges []InstanceStateChange `xml:"instancesSet>item"`
}

// StartInstances starts an instance that you've previously stopped.
//
// See http://cloud.nifty.com/api/rest/StartInstances.htm for more details.
func (compute *Compute) StartInstances(ids ...string) (resp *StartInstanceResp, err error) {
	params := makeParams("StartInstances")
	addParamsList(params, "InstanceId", ids)
	resp = &StartInstanceResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// StopInstances requests stopping one or more instances.
//
// See http://cloud.nifty.com/api/rest/StopInstances.htm for more details.
func (compute *Compute) StopInstances(options *StopInstancesOptions) (resp *StopInstanceResp, err error) {
	params := makeParams("StopInstances")
	addParamsList(params, "InstanceId", options.InstanceIds)
	if options.Force {
		params["Force"] = "true"
	}
	resp = &StopInstanceResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RebootInstance requests a reboot of one or more instances. This operation is asynchronous;
// it only queues a request to reboot the specified instance(s). The operation will succeed
// if the instances are valid and belong to you.
//
// Requests to reboot terminated instances are ignored.
//
// See http://cloud.nifty.com/api/rest/RebootInstances.htm for more details.
func (compute *Compute) RebootInstances(options *RebootInstancesOptions) (resp *SimpleResp, err error) {
	params := makeParams("RebootInstances")
	addParamsList(params, "InstanceId", options.InstanceIds)
	if options.Force {
		params["Force"] = "true"
	}
	resp = &SimpleResp{}
	err = compute.query(params, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// The ModifyInstanceAttribute request parameters.
type ModifyInstance struct {
	InstanceType          string
	BlockDevices          []BlockDeviceMapping
	DisableAPITermination bool
	SecurityGroups        []SecurityGroup
	SourceDestCheck       bool
	UserData              []byte
}

// Response to a ModifyInstanceAttribute request.
//
// http://cloud.nifty.com/api/rest/ModifyInstanceAttribute.htm for more details.
type ModifyInstanceResp struct {
	RequestId string `xml:"requestId"`
	Return    bool   `xml:"return"`
}

// ModifyImageAttribute modifies the specified attribute of the specified instance.
// You can specify only one attribute at a time. To modify some attributes, the
// instance must be stopped.
//
// See http://cloud.nifty.com/api/rest/ModifyInstanceAttribute.htm for more details.
func (compute *Compute) ModifyInstance(instId string, options *ModifyInstance) (resp *ModifyInstanceResp, err error) {
	params := makeParams("ModifyInstanceAttribute")
	params["InstanceId"] = instId
	addBlockDeviceParams("", params, options.BlockDevices)

	if options.InstanceType != "" {
		params["InstanceType.Value"] = options.InstanceType
	}

	if options.DisableAPITermination {
		params["DisableApiTermination.Value"] = "true"
	}

	if options.UserData != nil {
		userData := make([]byte, b64.EncodedLen(len(options.UserData)))
		b64.Encode(userData, options.UserData)
		params["UserData"] = string(userData)
	}

	i := 1
	for _, g := range options.SecurityGroups {
		if g.Id != "" {
			params["GroupId."+strconv.Itoa(i)] = g.Id
			i++
		}
	}

	resp = &ModifyInstanceResp{}
	err = compute.query(params, resp)
	if err != nil {
		resp = nil
	}
	return
}
