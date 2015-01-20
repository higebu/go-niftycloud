package compute_test

var ErrorDump = `
<?xml version="1.0" encoding="UTF-8"?>
<Response><Errors><Error><Code>UnsupportedOperation</Code>
<Message>NMIs with an instance-store root device are not supported for the instance type 'mini'.</Message>
</Error></Errors><RequestID>0503f4e9-bbd6-483c-b54f-c4ae9f3b30f4</RequestID></Response>
`

var RunInstancesExample = `
<RunInstancesResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <reservationId>r-47a5402e</reservationId>
  <ownerId>999988887777</ownerId>
  <groupSet>
      <item>
          <groupId>sg-67ad940e</groupId>
          <groupName>default</groupName>
      </item>
  </groupSet>
  <instancesSet>
    <item>
      <instanceId>2ba64342</instanceId>
      <imageId>29</imageId>
      <instanceState>
        <code>0</code>
        <name>pending</name>
      </instanceState>
      <keyName>example-key-name</keyName>
      <instanceType>small</instanceType>
      <launchTime>2007-08-07T11:51:50.000Z</launchTime>
      <placement>
        <availabilityZone>jp-east-11</availabilityZone>
      </placement>
      <clientToken/>
    </item>
    <item>
      <instanceId>2bc64242</instanceId>
      <imageId>29</imageId>
      <instanceState>
        <code>0</code>
        <name>pending</name>
      </instanceState>
      <keyName>example-key-name</keyName>
      <instanceType>small</instanceType>
      <launchTime>2007-08-07T11:51:50.000Z</launchTime>
      <placement>
         <availabilityZone>jp-east-11</availabilityZone>
      </placement>
      <clientToken/>
    </item>
    <item>
      <instanceId>2be64332</instanceId>
      <imageId>29</imageId>
      <instanceState>
        <code>0</code>
        <name>pending</name>
      </instanceState>
      <keyName>example-key-name</keyName>
      <instanceType>small</instanceType>
      <launchTime>2007-08-07T11:51:50.000Z</launchTime>
      <placement>
         <availabilityZone>jp-east-11</availabilityZone>
      </placement>
      <clientToken/>
    </item>
  </instancesSet>
</RunInstancesResponse>
`

var TerminateInstancesExample = `
<TerminateInstancesResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <instancesSet>
    <item>
      <instanceId>3ea74257</instanceId>
      <currentState>
        <code>32</code>
        <name>shutting-down</name>
      </currentState>
      <previousState>
        <code>16</code>
        <name>running</name>
      </previousState>
    </item>
  </instancesSet>
</TerminateInstancesResponse>
`

var DescribeInstancesExample1 = `
<DescribeInstancesResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
  <requestId>98e3c9a4-848c-4d6d-8e8a-b1bdEXAMPLE</requestId>
  <reservationSet>
    <item>
      <reservationId>r-b27e30d9</reservationId>
      <ownerId>999988887777</ownerId>
      <groupSet>
        <item>
          <groupId>sg-67ad940e</groupId>
          <groupName>default</groupName>
        </item>
      </groupSet>
      <instancesSet>
        <item>
          <instanceId>c5cd56af</instanceId>
          <imageId>30</imageId>
          <instanceState>
            <code>16</code>
            <name>running</name>
          </instanceState>
          <reason/>
          <keyName>GSG_Keypair</keyName>
          <productCodes/>
          <instanceType>small</instanceType>
          <launchTime>2010-08-17T01:15:18.000Z</launchTime>
          <placement>
            <availabilityZone>jp-east-11</availabilityZone>
            <groupName/>
          </placement>
          <privateIpAddress>10.198.85.190</privateIpAddress>
          <ipAddress>174.129.165.232</ipAddress>
          <architecture>i386</architecture>
          <rootDeviceType>disk</rootDeviceType>
          <rootDeviceName>/dev/sda1</rootDeviceName>
          <blockDeviceMapping>
            <item>
              <deviceName>/dev/sda1</deviceName>
              <ebs>
                <volumeId>vol-a082c1c9</volumeId>
                <status>attached</status>
                <attachTime>2010-08-17T01:15:21.000Z</attachTime>
                <deleteOnTermination>false</deleteOnTermination>
              </ebs>
            </item>
          </blockDeviceMapping>
          <clientToken/>
       </item>
      </instancesSet>
      <requesterId>854251627541</requesterId>
    </item>
    <item>
      <reservationId>r-b67e30dd</reservationId>
      <ownerId>999988887777</ownerId>
      <groupSet>
        <item>
          <groupId>sg-67ad940e</groupId>
          <groupName>default</groupName>
        </item>
      </groupSet>
      <instancesSet>
        <item>
          <instanceId>d9cd56b3</instanceId>
          <imageId>30</imageId>
          <instanceState>
            <code>16</code>
            <name>running</name>
          </instanceState>
          <reason/>
          <keyName>GSG_Keypair</keyName>
          <productCodes/>
          <instanceType>large</instanceType>
          <launchTime>2010-08-17T01:15:19.000Z</launchTime>
          <placement>
            <availabilityZone>jp-east-11</availabilityZone>
            <groupName/>
          </placement>
          <privateIpAddress>10.198.87.19</privateIpAddress>
          <ipAddress>184.73.58.78</ipAddress>
          <architecture>i386</architecture>
          <rootDeviceType>disk</rootDeviceType>
          <rootDeviceName>/dev/sda1</rootDeviceName>
          <blockDeviceMapping>
            <item>
              <deviceName>/dev/sda1</deviceName>
              <ebs>
                <volumeId>vol-a282c1cb</volumeId>
                <status>attached</status>
                <attachTime>2010-08-17T01:15:23.000Z</attachTime>
                <deleteOnTermination>false</deleteOnTermination>
              </ebs>
            </item>
          </blockDeviceMapping>
          <clientToken/>
       </item>
      </instancesSet>
      <requesterId>854251627541</requesterId>
    </item>
  </reservationSet>
</DescribeInstancesResponse>
`

var DescribeInstancesExample2 = `
<DescribeInstancesResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <reservationSet>
    <item>
      <reservationId>r-bc7e30d7</reservationId>
      <ownerId>999988887777</ownerId>
      <groupSet>
        <item>
          <groupId>sg-67ad940e</groupId>
          <groupName>default</groupName>
        </item>
      </groupSet>
      <instancesSet>
        <item>
          <instanceId>c7cd56ad</instanceId>
          <imageId>31</imageId>
          <instanceState>
            <code>16</code>
            <name>running</name>
          </instanceState>
          <keyName>GSG_Keypair</keyName>
          <productCodes/>
          <instanceType>small</instanceType>
          <launchTime>2010-08-17T01:15:16.000Z</launchTime>
          <placement>
              <availabilityZone>jp-east-11</availabilityZone>
          </placement>
          <privateIpAddress>10.255.121.240</privateIpAddress>
          <ipAddress>72.44.52.124</ipAddress>
          <architecture>i386</architecture>
          <rootDeviceType>disk</rootDeviceType>
          <rootDeviceName>/dev/sda1</rootDeviceName>
          <blockDeviceMapping>
              <item>
                 <deviceName>/dev/sda1</deviceName>
                 <ebs>
                    <volumeId>vol-a482c1cd</volumeId>
                    <status>attached</status>
                    <attachTime>2010-08-17T01:15:26.000Z</attachTime>
                    <deleteOnTermination>true</deleteOnTermination>
                </ebs>
             </item>
          </blockDeviceMapping>
          <clientToken/>
        </item>
      </instancesSet>
    </item>
  </reservationSet>
</DescribeInstancesResponse>
`

var ModifyInstanceExample = `
<ModifyImageAttributeResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <return>true</return>
</ModifyImageAttributeResponse>
`

var CreateImageExample = `
<CreateImageResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
   <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
   <imageId>32</imageId>
</CreateImageResponse>
`

var DescribeImagesExample = `
<DescribeImagesResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
         <requestId>4a4a27a2-2e7c-475d-b35b-ca822EXAMPLE</requestId>
    <imagesSet>
        <item>
            <imageId>29</imageId>
            <imageLocation></imageLocation>
            <imageState>available</imageState>
            <imageOwnerId>niftycloud</imageOwnerId>
            <productcodes></productcodes>
            <architecture>x86_64</architecture>
            <imageType>machine</imageType>
            <imageOwnerAlias>ニフティ株式会社</imageOwnerAlias>
            <name>CentOS 6.4 64bit Plain</name>
            <description></description>
            <rootDeviceType>disk</rootDeviceType>
            <rootDeviceName></rootDeviceName>
            <blockDeviceMapping>
                <item>
                    <deviceName>/dev/sda1</deviceName>
                    <ebs>
                        <snapshotId>snap-787e9403</snapshotId>
                        <volumeSize>8</volumeSize>
                        <deleteOnTermination>true</deleteOnTermination>
                    </ebs>
                </item>
            </blockDeviceMapping>
        </item>
    </imagesSet>
</DescribeImagesResponse>
`

var ImageAttributeExample = `
<DescribeImageAttributeResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
   <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
   <imageId>33</imageId>
   <launchPermission>
      <item>
         <group>all</group>
      </item>
      <item>
         <userId>495219933132</userId>
      </item>
   </launchPermission>
</DescribeImageAttributeResponse>
`

var ModifyImageAttributeExample = `
<ModifyImageAttributeResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <return>true</return>
</ModifyImageAttributeResponse>
`

var CreateSecurityGroupExample = `
<CreateSecurityGroupResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
   <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
   <return>true</return>
   <groupId>sg-67ad940e</groupId>
</CreateSecurityGroupResponse>
`

var DescribeSecurityGroupsExample = `
<DescribeSecurityGroupsResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <securityGroupInfo>
    <item>
      <ownerId>999988887777</ownerId>
      <groupName>WebServers</groupName>
      <groupId>sg-67ad940e</groupId>
      <groupDescription>Web Servers</groupDescription>
      <ipPermissions>
        <item>
           <ipProtocol>tcp</ipProtocol>
           <fromPort>80</fromPort>
           <toPort>80</toPort>
           <groups/>
           <ipRanges>
             <item>
               <cidrIp>0.0.0.0/0</cidrIp>
             </item>
           </ipRanges>
        </item>
      </ipPermissions>
    </item>
    <item>
      <ownerId>999988887777</ownerId>
      <groupName>RangedPortsBySource</groupName>
      <groupId>sg-76abc467</groupId>
      <groupDescription>Group A</groupDescription>
      <ipPermissions>
        <item>
           <ipProtocol>tcp</ipProtocol>
           <fromPort>6000</fromPort>
           <toPort>7000</toPort>
           <groups/>
           <ipRanges/>
        </item>
      </ipPermissions>
    </item>
  </securityGroupInfo>
</DescribeSecurityGroupsResponse>
`

// A dump which includes groups within ip permissions.
var DescribeSecurityGroupsDump = `
<?xml version="1.0" encoding="UTF-8"?>
<DescribeSecurityGroupsResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
    <requestId>87b92b57-cc6e-48b2-943f-f6f0e5c9f46c</requestId>
    <securityGroupInfo>
        <item>
            <ownerId>12345</ownerId>
            <groupName>default</groupName>
            <groupDescription>default group</groupDescription>
            <ipPermissions>
                <item>
                    <ipProtocol>icmp</ipProtocol>
                    <fromPort>-1</fromPort>
                    <toPort>-1</toPort>
                    <groups>
                        <item>
                            <userId>12345</userId>
                            <groupName>default</groupName>
                            <groupId>sg-67ad940e</groupId>
                        </item>
                    </groups>
                    <ipRanges/>
                </item>
                <item>
                    <ipProtocol>tcp</ipProtocol>
                    <fromPort>0</fromPort>
                    <toPort>65535</toPort>
                    <groups>
                        <item>
                            <userId>12345</userId>
                            <groupName>other</groupName>
                            <groupId>sg-76abc467</groupId>
                        </item>
                    </groups>
                    <ipRanges/>
                </item>
            </ipPermissions>
        </item>
    </securityGroupInfo>
</DescribeSecurityGroupsResponse>
`

var DeleteSecurityGroupExample = `
<DeleteSecurityGroupResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
   <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
   <return>true</return>
</DeleteSecurityGroupResponse>
`

var AuthorizeSecurityGroupIngressExample = `
<AuthorizeSecurityGroupIngressResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <return>true</return>
</AuthorizeSecurityGroupIngressResponse>
`

var RevokeSecurityGroupIngressExample = `
<RevokeSecurityGroupIngressResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <return>true</return>
</RevokeSecurityGroupIngressResponse>
`

var StartInstancesExample = `
<StartInstancesResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <instancesSet>
    <item>
      <instanceId>10a64379</instanceId>
      <currentState>
          <code>0</code>
          <name>pending</name>
      </currentState>
      <previousState>
          <code>80</code>
          <name>stopped</name>
      </previousState>
    </item>
  </instancesSet>
</StartInstancesResponse>
`

var StopInstancesExample = `
<StopInstancesResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <instancesSet>
    <item>
      <instanceId>10a64379</instanceId>
      <currentState>
          <code>64</code>
          <name>stopping</name>
      </currentState>
      <previousState>
          <code>16</code>
          <name>running</name>
      </previousState>
    </item>
  </instancesSet>
</StopInstancesResponse>
`

var RebootInstancesExample = `
<RebootInstancesResponse xmlns="https://cp.cloud.nifty.com/api/1.19/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <return>true</return>
</RebootInstancesResponse>
`
