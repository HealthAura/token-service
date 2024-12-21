package awsec2

import (
	_init_ "github.com/aws/aws-cdk-go/awscdk/v2/jsii"
	_jsii_ "github.com/aws/jsii-runtime-go/runtime"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2/internal"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/constructs-go/constructs/v10"
)

// This represents a single EC2 instance.
//
// Example:
//   var vpc iVpc
//
//   lb := elb.NewLoadBalancer(this, jsii.String("LB"), &LoadBalancerProps{
//   	Vpc: Vpc,
//   	InternetFacing: jsii.Boolean(true),
//   })
//
//   // instance to add as the target for load balancer.
//   instance := ec2.NewInstance(this, jsii.String("targetInstance"), &InstanceProps{
//   	Vpc: vpc,
//   	InstanceType: ec2.InstanceType_Of(ec2.InstanceClass_BURSTABLE2, ec2.InstanceSize_MICRO),
//   	MachineImage: ec2.NewAmazonLinuxImage(&AmazonLinuxImageProps{
//   		Generation: ec2.AmazonLinuxGeneration_AMAZON_LINUX_2,
//   	}),
//   })
//   lb.AddTarget(elb.NewInstanceTarget(instance))
//
type Instance interface {
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
	// the underlying instance resource.
	Instance() CfnInstance
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
	// The type of OS the instance is running.
	OsType() OperatingSystemType
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
	// UserData for the instance.
	UserData() UserData
	// Add the security group to the instance.
	AddSecurityGroup(securityGroup ISecurityGroup)
	// Adds a statement to the IAM role assumed by the instance.
	AddToRolePolicy(statement awsiam.PolicyStatement)
	// Add command to the startup script of the instance.
	//
	// The command must be in the scripting language supported by the instance's OS (i.e. Linux/Windows).
	AddUserData(commands ...*string)
	// Use a CloudFormation Init configuration at instance startup.
	//
	// This does the following:
	//
	// - Attaches the CloudFormation Init metadata to the Instance resource.
	// - Add commands to the instance UserData to run `cfn-init` and `cfn-signal`.
	// - Update the instance's CreationPolicy to wait for the `cfn-signal` commands.
	ApplyCloudFormationInit(init CloudFormationInit, options *ApplyCloudFormationInitOptions)
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

// The jsii proxy struct for Instance
type jsiiProxy_Instance struct {
	internal.Type__awscdkResource
	jsiiProxy_IInstance
}

func (j *jsiiProxy_Instance) Connections() Connections {
	var returns Connections
	_jsii_.Get(
		j,
		"connections",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) Env() *awscdk.ResourceEnvironment {
	var returns *awscdk.ResourceEnvironment
	_jsii_.Get(
		j,
		"env",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) GrantPrincipal() awsiam.IPrincipal {
	var returns awsiam.IPrincipal
	_jsii_.Get(
		j,
		"grantPrincipal",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) Instance() CfnInstance {
	var returns CfnInstance
	_jsii_.Get(
		j,
		"instance",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) InstanceAvailabilityZone() *string {
	var returns *string
	_jsii_.Get(
		j,
		"instanceAvailabilityZone",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) InstanceId() *string {
	var returns *string
	_jsii_.Get(
		j,
		"instanceId",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) InstancePrivateDnsName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"instancePrivateDnsName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) InstancePrivateIp() *string {
	var returns *string
	_jsii_.Get(
		j,
		"instancePrivateIp",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) InstancePublicDnsName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"instancePublicDnsName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) InstancePublicIp() *string {
	var returns *string
	_jsii_.Get(
		j,
		"instancePublicIp",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) Node() constructs.Node {
	var returns constructs.Node
	_jsii_.Get(
		j,
		"node",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) OsType() OperatingSystemType {
	var returns OperatingSystemType
	_jsii_.Get(
		j,
		"osType",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) PhysicalName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"physicalName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) Role() awsiam.IRole {
	var returns awsiam.IRole
	_jsii_.Get(
		j,
		"role",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) Stack() awscdk.Stack {
	var returns awscdk.Stack
	_jsii_.Get(
		j,
		"stack",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Instance) UserData() UserData {
	var returns UserData
	_jsii_.Get(
		j,
		"userData",
		&returns,
	)
	return returns
}


func NewInstance(scope constructs.Construct, id *string, props *InstanceProps) Instance {
	_init_.Initialize()

	if err := validateNewInstanceParameters(scope, id, props); err != nil {
		panic(err)
	}
	j := jsiiProxy_Instance{}

	_jsii_.Create(
		"aws-cdk-lib.aws_ec2.Instance",
		[]interface{}{scope, id, props},
		&j,
	)

	return &j
}

func NewInstance_Override(i Instance, scope constructs.Construct, id *string, props *InstanceProps) {
	_init_.Initialize()

	_jsii_.Create(
		"aws-cdk-lib.aws_ec2.Instance",
		[]interface{}{scope, id, props},
		i,
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
func Instance_IsConstruct(x interface{}) *bool {
	_init_.Initialize()

	if err := validateInstance_IsConstructParameters(x); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ec2.Instance",
		"isConstruct",
		[]interface{}{x},
		&returns,
	)

	return returns
}

// Returns true if the construct was created by CDK, and false otherwise.
func Instance_IsOwnedResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateInstance_IsOwnedResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ec2.Instance",
		"isOwnedResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

// Check whether the given construct is a Resource.
func Instance_IsResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateInstance_IsResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ec2.Instance",
		"isResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

func (i *jsiiProxy_Instance) AddSecurityGroup(securityGroup ISecurityGroup) {
	if err := i.validateAddSecurityGroupParameters(securityGroup); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		i,
		"addSecurityGroup",
		[]interface{}{securityGroup},
	)
}

func (i *jsiiProxy_Instance) AddToRolePolicy(statement awsiam.PolicyStatement) {
	if err := i.validateAddToRolePolicyParameters(statement); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		i,
		"addToRolePolicy",
		[]interface{}{statement},
	)
}

func (i *jsiiProxy_Instance) AddUserData(commands ...*string) {
	args := []interface{}{}
	for _, a := range commands {
		args = append(args, a)
	}

	_jsii_.InvokeVoid(
		i,
		"addUserData",
		args,
	)
}

func (i *jsiiProxy_Instance) ApplyCloudFormationInit(init CloudFormationInit, options *ApplyCloudFormationInitOptions) {
	if err := i.validateApplyCloudFormationInitParameters(init, options); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		i,
		"applyCloudFormationInit",
		[]interface{}{init, options},
	)
}

func (i *jsiiProxy_Instance) ApplyRemovalPolicy(policy awscdk.RemovalPolicy) {
	if err := i.validateApplyRemovalPolicyParameters(policy); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		i,
		"applyRemovalPolicy",
		[]interface{}{policy},
	)
}

func (i *jsiiProxy_Instance) GeneratePhysicalName() *string {
	var returns *string

	_jsii_.Invoke(
		i,
		"generatePhysicalName",
		nil, // no parameters
		&returns,
	)

	return returns
}

func (i *jsiiProxy_Instance) GetResourceArnAttribute(arnAttr *string, arnComponents *awscdk.ArnComponents) *string {
	if err := i.validateGetResourceArnAttributeParameters(arnAttr, arnComponents); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		i,
		"getResourceArnAttribute",
		[]interface{}{arnAttr, arnComponents},
		&returns,
	)

	return returns
}

func (i *jsiiProxy_Instance) GetResourceNameAttribute(nameAttr *string) *string {
	if err := i.validateGetResourceNameAttributeParameters(nameAttr); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		i,
		"getResourceNameAttribute",
		[]interface{}{nameAttr},
		&returns,
	)

	return returns
}

func (i *jsiiProxy_Instance) ToString() *string {
	var returns *string

	_jsii_.Invoke(
		i,
		"toString",
		nil, // no parameters
		&returns,
	)

	return returns
}

