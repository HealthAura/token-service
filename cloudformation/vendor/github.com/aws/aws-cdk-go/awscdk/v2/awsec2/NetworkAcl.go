package awsec2

import (
	_init_ "github.com/aws/aws-cdk-go/awscdk/v2/jsii"
	_jsii_ "github.com/aws/jsii-runtime-go/runtime"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2/internal"
	"github.com/aws/constructs-go/constructs/v10"
)

// Define a new custom network ACL.
//
// By default, will deny all inbound and outbound traffic unless entries are
// added explicitly allowing it.
//
// Example:
//   // The code below shows an example of how to instantiate this type.
//   // The values are placeholders you should change.
//   import "github.com/aws/aws-cdk-go/awscdk"
//
//   var subnet subnet
//   var subnetFilter subnetFilter
//   var vpc vpc
//
//   networkAcl := awscdk.Aws_ec2.NewNetworkAcl(this, jsii.String("MyNetworkAcl"), &NetworkAclProps{
//   	Vpc: vpc,
//
//   	// the properties below are optional
//   	NetworkAclName: jsii.String("networkAclName"),
//   	SubnetSelection: &SubnetSelection{
//   		AvailabilityZones: []*string{
//   			jsii.String("availabilityZones"),
//   		},
//   		OnePerAz: jsii.Boolean(false),
//   		SubnetFilters: []*subnetFilter{
//   			subnetFilter,
//   		},
//   		SubnetGroupName: jsii.String("subnetGroupName"),
//   		Subnets: []iSubnet{
//   			subnet,
//   		},
//   		SubnetType: awscdk.*Aws_ec2.SubnetType_PRIVATE_ISOLATED,
//   	},
//   })
//
type NetworkAcl interface {
	awscdk.Resource
	INetworkAcl
	// The environment this resource belongs to.
	//
	// For resources that are created and managed by the CDK
	// (generally, those created by creating new class instances like Role, Bucket, etc.),
	// this is always the same as the environment of the stack they belong to;
	// however, for imported resources
	// (those obtained from static methods like fromRoleArn, fromBucketName, etc.),
	// that might be different than the stack they were imported into.
	Env() *awscdk.ResourceEnvironment
	// The ID of the NetworkACL.
	NetworkAclId() *string
	// The VPC ID for this NetworkACL.
	NetworkAclVpcId() *string
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
	// The stack in which this resource is defined.
	Stack() awscdk.Stack
	// Add a new entry to the ACL.
	AddEntry(id *string, options *CommonNetworkAclEntryOptions) NetworkAclEntry
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
	// Associate the ACL with a given set of subnets.
	AssociateWithSubnet(id *string, selection *SubnetSelection)
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

// The jsii proxy struct for NetworkAcl
type jsiiProxy_NetworkAcl struct {
	internal.Type__awscdkResource
	jsiiProxy_INetworkAcl
}

func (j *jsiiProxy_NetworkAcl) Env() *awscdk.ResourceEnvironment {
	var returns *awscdk.ResourceEnvironment
	_jsii_.Get(
		j,
		"env",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_NetworkAcl) NetworkAclId() *string {
	var returns *string
	_jsii_.Get(
		j,
		"networkAclId",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_NetworkAcl) NetworkAclVpcId() *string {
	var returns *string
	_jsii_.Get(
		j,
		"networkAclVpcId",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_NetworkAcl) Node() constructs.Node {
	var returns constructs.Node
	_jsii_.Get(
		j,
		"node",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_NetworkAcl) PhysicalName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"physicalName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_NetworkAcl) Stack() awscdk.Stack {
	var returns awscdk.Stack
	_jsii_.Get(
		j,
		"stack",
		&returns,
	)
	return returns
}


func NewNetworkAcl(scope constructs.Construct, id *string, props *NetworkAclProps) NetworkAcl {
	_init_.Initialize()

	if err := validateNewNetworkAclParameters(scope, id, props); err != nil {
		panic(err)
	}
	j := jsiiProxy_NetworkAcl{}

	_jsii_.Create(
		"aws-cdk-lib.aws_ec2.NetworkAcl",
		[]interface{}{scope, id, props},
		&j,
	)

	return &j
}

func NewNetworkAcl_Override(n NetworkAcl, scope constructs.Construct, id *string, props *NetworkAclProps) {
	_init_.Initialize()

	_jsii_.Create(
		"aws-cdk-lib.aws_ec2.NetworkAcl",
		[]interface{}{scope, id, props},
		n,
	)
}

// Import an existing NetworkAcl into this app.
func NetworkAcl_FromNetworkAclId(scope constructs.Construct, id *string, networkAclId *string) INetworkAcl {
	_init_.Initialize()

	if err := validateNetworkAcl_FromNetworkAclIdParameters(scope, id, networkAclId); err != nil {
		panic(err)
	}
	var returns INetworkAcl

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ec2.NetworkAcl",
		"fromNetworkAclId",
		[]interface{}{scope, id, networkAclId},
		&returns,
	)

	return returns
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
func NetworkAcl_IsConstruct(x interface{}) *bool {
	_init_.Initialize()

	if err := validateNetworkAcl_IsConstructParameters(x); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ec2.NetworkAcl",
		"isConstruct",
		[]interface{}{x},
		&returns,
	)

	return returns
}

// Returns true if the construct was created by CDK, and false otherwise.
func NetworkAcl_IsOwnedResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateNetworkAcl_IsOwnedResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ec2.NetworkAcl",
		"isOwnedResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

// Check whether the given construct is a Resource.
func NetworkAcl_IsResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateNetworkAcl_IsResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ec2.NetworkAcl",
		"isResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

func (n *jsiiProxy_NetworkAcl) AddEntry(id *string, options *CommonNetworkAclEntryOptions) NetworkAclEntry {
	if err := n.validateAddEntryParameters(id, options); err != nil {
		panic(err)
	}
	var returns NetworkAclEntry

	_jsii_.Invoke(
		n,
		"addEntry",
		[]interface{}{id, options},
		&returns,
	)

	return returns
}

func (n *jsiiProxy_NetworkAcl) ApplyRemovalPolicy(policy awscdk.RemovalPolicy) {
	if err := n.validateApplyRemovalPolicyParameters(policy); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		n,
		"applyRemovalPolicy",
		[]interface{}{policy},
	)
}

func (n *jsiiProxy_NetworkAcl) AssociateWithSubnet(id *string, selection *SubnetSelection) {
	if err := n.validateAssociateWithSubnetParameters(id, selection); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		n,
		"associateWithSubnet",
		[]interface{}{id, selection},
	)
}

func (n *jsiiProxy_NetworkAcl) GeneratePhysicalName() *string {
	var returns *string

	_jsii_.Invoke(
		n,
		"generatePhysicalName",
		nil, // no parameters
		&returns,
	)

	return returns
}

func (n *jsiiProxy_NetworkAcl) GetResourceArnAttribute(arnAttr *string, arnComponents *awscdk.ArnComponents) *string {
	if err := n.validateGetResourceArnAttributeParameters(arnAttr, arnComponents); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		n,
		"getResourceArnAttribute",
		[]interface{}{arnAttr, arnComponents},
		&returns,
	)

	return returns
}

func (n *jsiiProxy_NetworkAcl) GetResourceNameAttribute(nameAttr *string) *string {
	if err := n.validateGetResourceNameAttributeParameters(nameAttr); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		n,
		"getResourceNameAttribute",
		[]interface{}{nameAttr},
		&returns,
	)

	return returns
}

func (n *jsiiProxy_NetworkAcl) ToString() *string {
	var returns *string

	_jsii_.Invoke(
		n,
		"toString",
		nil, // no parameters
		&returns,
	)

	return returns
}

