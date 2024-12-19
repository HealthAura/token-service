package awsec2

import (
	_init_ "github.com/aws/aws-cdk-go/awscdk/v2/jsii"
	_jsii_ "github.com/aws/jsii-runtime-go/runtime"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2/internal"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/constructs-go/constructs/v10"
)

// This creates a linux bastion host you can use to connect to other instances or services in your VPC.
//
// The recommended way to connect to the bastion host is by using AWS Systems Manager Session Manager.
//
// The operating system is Amazon Linux 2 with the latest SSM agent installed
//
// You can also configure this bastion host to allow connections via SSH.
//
// Example:
//   host := ec2.NewBastionHostLinux(this, jsii.String("BastionHost"), &BastionHostLinuxProps{
//   	Vpc: Vpc,
//   	BlockDevices: []blockDevice{
//   		&blockDevice{
//   			DeviceName: jsii.String("/dev/sdh"),
//   			Volume: ec2.BlockDeviceVolume_Ebs(jsii.Number(10), &EbsDeviceOptions{
//   				Encrypted: jsii.Boolean(true),
//   			}),
//   		},
//   	},
//   })
//
type BastionHostLinux interface {
	awscdk.Resource
	IInstance
	// Allows specify security group connections for the instance.
	Connections() Connections
	// The environment this resource belongs to.
	//
	// For resources that are created and managed by the CDK
	// (generally, those created by creating new class instances like Role, Bucket, etc.),
	// this is always the same as the environment of the stack they belong to;
	// however, for imported resources
	// (those obtained from static methods like fromRoleArn, fromBucketName, etc.),
	// that might be different than the stack they were imported into.
	Env() *awscdk.ResourceEnvironment
	// The principal to grant permissions to.
	GrantPrincipal() awsiam.IPrincipal
	// The underlying instance resource.
	Instance() Instance
	// The availability zone the instance was launched in.
	InstanceAvailabilityZone() *string
	// The instance's ID.
	InstanceId() *string
	// Private DNS name for this instance.
	InstancePrivateDnsName() *string
	// Private IP for this instance.
	InstancePrivateIp() *string
	// Publicly-routable DNS name for this instance.
	//
	// (May be an empty string if the instance does not have a public name).
	InstancePublicDnsName() *string
	// Publicly-routable IP  address for this instance.
	//
	// (May be an empty string if the instance does not have a public IP).
	InstancePublicIp() *string
	// The tree node.
	Node() constructs.Node
	// Returns a string-encoded token that resolves to the physical name that should be passed to the CloudFormation resource.
	//
	// This value will resolve to one of the following:
	// - a concrete value (e.g. `"my-awesome-bucket"`)
	// - `undefined`, when a name should be generated by CloudFormation
	// - a concrete name generated automatically during synthesis, in
	//   cross-environment scenarios.
	PhysicalName() *string
	// The IAM role assumed by the instance.
	Role() awsiam.IRole
	// The stack in which this resource is defined.
	Stack() awscdk.Stack
	// Allow SSH access from the given peer or peers.
	//
	// Necessary if you want to connect to the instance using ssh. If not
	// called, you should use SSM Session Manager to connect to the instance.
	AllowSshAccessFrom(peer ...IPeer)
	// Apply the given removal policy to this resource.
	//
	// The Removal Policy controls what happens to this resource when it stops
	// being managed by CloudFormation, either because you've removed it from the
	// CDK application or because you've made a change that requires the resource
	// to be replaced.
	//
	// The resource can be deleted (`RemovalPolicy.DESTROY`), or left in your AWS
	// account for data recovery and cleanup later (`RemovalPolicy.RETAIN`).
	ApplyRemovalPolicy(policy awscdk.RemovalPolicy)
	GeneratePhysicalName() *string
	// Returns an environment-sensitive token that should be used for the resource's "ARN" attribute (e.g. `bucket.bucketArn`).
	//
	// Normally, this token will resolve to `arnAttr`, but if the resource is
	// referenced across environments, `arnComponents` will be used to synthesize
	// a concrete ARN with the resource's physical name. Make sure to reference
	// `this.physicalName` in `arnComponents`.
	GetResourceArnAttribute(arnAttr *string, arnComponents *awscdk.ArnComponents) *string
	// Returns an environment-sensitive token that should be used for the resource's "name" attribute (e.g. `bucket.bucketName`).
	//
	// Normally, this token will resolve to `nameAttr`, but if the resource is
	// referenced across environments, it will be resolved to `this.physicalName`,
	// which will be a concrete name.
	GetResourceNameAttribute(nameAttr *string) *string
	// Returns a string representation of this construct.
	ToString() *string
}

// The jsii proxy struct for BastionHostLinux
type jsiiProxy_BastionHostLinux struct {
	internal.Type__awscdkResource
	jsiiProxy_IInstance
}

func (j *jsiiProxy_BastionHostLinux) Connections() Connections {
	var returns Connections
	_jsii_.Get(
		j,
		"connections",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) Env() *awscdk.ResourceEnvironment {
	var returns *awscdk.ResourceEnvironment
	_jsii_.Get(
		j,
		"env",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) GrantPrincipal() awsiam.IPrincipal {
	var returns awsiam.IPrincipal
	_jsii_.Get(
		j,
		"grantPrincipal",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) Instance() Instance {
	var returns Instance
	_jsii_.Get(
		j,
		"instance",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) InstanceAvailabilityZone() *string {
	var returns *string
	_jsii_.Get(
		j,
		"instanceAvailabilityZone",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) InstanceId() *string {
	var returns *string
	_jsii_.Get(
		j,
		"instanceId",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) InstancePrivateDnsName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"instancePrivateDnsName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) InstancePrivateIp() *string {
	var returns *string
	_jsii_.Get(
		j,
		"instancePrivateIp",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) InstancePublicDnsName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"instancePublicDnsName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) InstancePublicIp() *string {
	var returns *string
	_jsii_.Get(
		j,
		"instancePublicIp",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) Node() constructs.Node {
	var returns constructs.Node
	_jsii_.Get(
		j,
		"node",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) PhysicalName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"physicalName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) Role() awsiam.IRole {
	var returns awsiam.IRole
	_jsii_.Get(
		j,
		"role",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_BastionHostLinux) Stack() awscdk.Stack {
	var returns awscdk.Stack
	_jsii_.Get(
		j,
		"stack",
		&returns,
	)
	return returns
}


func NewBastionHostLinux(scope constructs.Construct, id *string, props *BastionHostLinuxProps) BastionHostLinux {
	_init_.Initialize()

	if err := validateNewBastionHostLinuxParameters(scope, id, props); err != nil {
		panic(err)
	}
	j := jsiiProxy_BastionHostLinux{}

	_jsii_.Create(
		"aws-cdk-lib.aws_ec2.BastionHostLinux",
		[]interface{}{scope, id, props},
		&j,
	)

	return &j
}

func NewBastionHostLinux_Override(b BastionHostLinux, scope constructs.Construct, id *string, props *BastionHostLinuxProps) {
	_init_.Initialize()

	_jsii_.Create(
		"aws-cdk-lib.aws_ec2.BastionHostLinux",
		[]interface{}{scope, id, props},
		b,
	)
}

// Checks if `x` is a construct.
//
// Use this method instead of `instanceof` to properly detect `Construct`
// instances, even when the construct library is symlinked.
//
// Explanation: in JavaScript, multiple copies of the `constructs` library on
// disk are seen as independent, completely different libraries. As a
// consequence, the class `Construct` in each copy of the `constructs` library
// is seen as a different class, and an instance of one class will not test as
// `instanceof` the other class. `npm install` will not create installations
// like this, but users may manually symlink construct libraries together or
// use a monorepo tool: in those cases, multiple copies of the `constructs`
// library can be accidentally installed, and `instanceof` will behave
// unpredictably. It is safest to avoid using `instanceof`, and using
// this type-testing method instead.
//
// Returns: true if `x` is an object created from a class which extends `Construct`.
func BastionHostLinux_IsConstruct(x interface{}) *bool {
	_init_.Initialize()

	if err := validateBastionHostLinux_IsConstructParameters(x); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ec2.BastionHostLinux",
		"isConstruct",
		[]interface{}{x},
		&returns,
	)

	return returns
}

// Returns true if the construct was created by CDK, and false otherwise.
func BastionHostLinux_IsOwnedResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateBastionHostLinux_IsOwnedResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ec2.BastionHostLinux",
		"isOwnedResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

// Check whether the given construct is a Resource.
func BastionHostLinux_IsResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateBastionHostLinux_IsResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ec2.BastionHostLinux",
		"isResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

func (b *jsiiProxy_BastionHostLinux) AllowSshAccessFrom(peer ...IPeer) {
	args := []interface{}{}
	for _, a := range peer {
		args = append(args, a)
	}

	_jsii_.InvokeVoid(
		b,
		"allowSshAccessFrom",
		args,
	)
}

func (b *jsiiProxy_BastionHostLinux) ApplyRemovalPolicy(policy awscdk.RemovalPolicy) {
	if err := b.validateApplyRemovalPolicyParameters(policy); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		b,
		"applyRemovalPolicy",
		[]interface{}{policy},
	)
}

func (b *jsiiProxy_BastionHostLinux) GeneratePhysicalName() *string {
	var returns *string

	_jsii_.Invoke(
		b,
		"generatePhysicalName",
		nil, // no parameters
		&returns,
	)

	return returns
}

func (b *jsiiProxy_BastionHostLinux) GetResourceArnAttribute(arnAttr *string, arnComponents *awscdk.ArnComponents) *string {
	if err := b.validateGetResourceArnAttributeParameters(arnAttr, arnComponents); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		b,
		"getResourceArnAttribute",
		[]interface{}{arnAttr, arnComponents},
		&returns,
	)

	return returns
}

func (b *jsiiProxy_BastionHostLinux) GetResourceNameAttribute(nameAttr *string) *string {
	if err := b.validateGetResourceNameAttributeParameters(nameAttr); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		b,
		"getResourceNameAttribute",
		[]interface{}{nameAttr},
		&returns,
	)

	return returns
}

func (b *jsiiProxy_BastionHostLinux) ToString() *string {
	var returns *string

	_jsii_.Invoke(
		b,
		"toString",
		nil, // no parameters
		&returns,
	)

	return returns
}

