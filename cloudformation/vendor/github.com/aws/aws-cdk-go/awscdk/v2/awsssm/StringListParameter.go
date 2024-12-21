package awsssm

import (
	_init_ "github.com/aws/aws-cdk-go/awscdk/v2/jsii"
	_jsii_ "github.com/aws/jsii-runtime-go/runtime"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awskms"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsssm/internal"
	"github.com/aws/constructs-go/constructs/v10"
)

// Creates a new StringList SSM Parameter.
//
// Example:
//   ssm.StringListParameter_ValueForTypedListParameter(this, jsii.String("/My/Public/Parameter"), ssm.ParameterValueType_AWS_EC2_IMAGE_ID)
//
type StringListParameter interface {
	awscdk.Resource
	IParameter
	IStringListParameter
	// The encryption key that is used to encrypt this parameter.
	// Default: - default master key.
	//
	EncryptionKey() awskms.IKey
	// The environment this resource belongs to.
	//
	// For resources that are created and managed by the CDK
	// (generally, those created by creating new class instances like Role, Bucket, etc.),
	// this is always the same as the environment of the stack they belong to;
	// however, for imported resources
	// (those obtained from static methods like fromRoleArn, fromBucketName, etc.),
	// that might be different than the stack they were imported into.
	Env() *awscdk.ResourceEnvironment
	// The tree node.
	Node() constructs.Node
	// The ARN of the SSM Parameter resource.
	ParameterArn() *string
	// The name of the SSM Parameter resource.
	ParameterName() *string
	// The type of the SSM Parameter resource.
	ParameterType() *string
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
	// The parameter value.
	//
	// Value must not nest another parameter. Do not use {{}} in the value. Values in the array
	// cannot contain commas (``,``).
	StringListValue() *[]*string
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
	// Grants read (DescribeParameter, GetParameters, GetParameter, GetParameterHistory) permissions on the SSM Parameter.
	GrantRead(grantee awsiam.IGrantable) awsiam.Grant
	// Grants write (PutParameter) permissions on the SSM Parameter.
	GrantWrite(grantee awsiam.IGrantable) awsiam.Grant
	// Returns a string representation of this construct.
	ToString() *string
}

// The jsii proxy struct for StringListParameter
type jsiiProxy_StringListParameter struct {
	internal.Type__awscdkResource
	jsiiProxy_IParameter
	jsiiProxy_IStringListParameter
}

func (j *jsiiProxy_StringListParameter) EncryptionKey() awskms.IKey {
	var returns awskms.IKey
	_jsii_.Get(
		j,
		"encryptionKey",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_StringListParameter) Env() *awscdk.ResourceEnvironment {
	var returns *awscdk.ResourceEnvironment
	_jsii_.Get(
		j,
		"env",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_StringListParameter) Node() constructs.Node {
	var returns constructs.Node
	_jsii_.Get(
		j,
		"node",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_StringListParameter) ParameterArn() *string {
	var returns *string
	_jsii_.Get(
		j,
		"parameterArn",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_StringListParameter) ParameterName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"parameterName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_StringListParameter) ParameterType() *string {
	var returns *string
	_jsii_.Get(
		j,
		"parameterType",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_StringListParameter) PhysicalName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"physicalName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_StringListParameter) Stack() awscdk.Stack {
	var returns awscdk.Stack
	_jsii_.Get(
		j,
		"stack",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_StringListParameter) StringListValue() *[]*string {
	var returns *[]*string
	_jsii_.Get(
		j,
		"stringListValue",
		&returns,
	)
	return returns
}


func NewStringListParameter(scope constructs.Construct, id *string, props *StringListParameterProps) StringListParameter {
	_init_.Initialize()

	if err := validateNewStringListParameterParameters(scope, id, props); err != nil {
		panic(err)
	}
	j := jsiiProxy_StringListParameter{}

	_jsii_.Create(
		"aws-cdk-lib.aws_ssm.StringListParameter",
		[]interface{}{scope, id, props},
		&j,
	)

	return &j
}

func NewStringListParameter_Override(s StringListParameter, scope constructs.Construct, id *string, props *StringListParameterProps) {
	_init_.Initialize()

	_jsii_.Create(
		"aws-cdk-lib.aws_ssm.StringListParameter",
		[]interface{}{scope, id, props},
		s,
	)
}

// Imports an external string list parameter with name and optional version.
func StringListParameter_FromListParameterAttributes(scope constructs.Construct, id *string, attrs *ListParameterAttributes) IStringListParameter {
	_init_.Initialize()

	if err := validateStringListParameter_FromListParameterAttributesParameters(scope, id, attrs); err != nil {
		panic(err)
	}
	var returns IStringListParameter

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ssm.StringListParameter",
		"fromListParameterAttributes",
		[]interface{}{scope, id, attrs},
		&returns,
	)

	return returns
}

// Imports an external parameter of type string list.
//
// Returns a token and should not be parsed.
func StringListParameter_FromStringListParameterName(scope constructs.Construct, id *string, stringListParameterName *string) IStringListParameter {
	_init_.Initialize()

	if err := validateStringListParameter_FromStringListParameterNameParameters(scope, id, stringListParameterName); err != nil {
		panic(err)
	}
	var returns IStringListParameter

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ssm.StringListParameter",
		"fromStringListParameterName",
		[]interface{}{scope, id, stringListParameterName},
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
func StringListParameter_IsConstruct(x interface{}) *bool {
	_init_.Initialize()

	if err := validateStringListParameter_IsConstructParameters(x); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ssm.StringListParameter",
		"isConstruct",
		[]interface{}{x},
		&returns,
	)

	return returns
}

// Returns true if the construct was created by CDK, and false otherwise.
func StringListParameter_IsOwnedResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateStringListParameter_IsOwnedResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ssm.StringListParameter",
		"isOwnedResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

// Check whether the given construct is a Resource.
func StringListParameter_IsResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateStringListParameter_IsResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ssm.StringListParameter",
		"isResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

// Returns a token that will resolve (during deployment) to the list value of an SSM StringList parameter.
func StringListParameter_ValueForTypedListParameter(scope constructs.Construct, parameterName *string, type_ ParameterValueType, version *float64) *[]*string {
	_init_.Initialize()

	if err := validateStringListParameter_ValueForTypedListParameterParameters(scope, parameterName); err != nil {
		panic(err)
	}
	var returns *[]*string

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_ssm.StringListParameter",
		"valueForTypedListParameter",
		[]interface{}{scope, parameterName, type_, version},
		&returns,
	)

	return returns
}

func (s *jsiiProxy_StringListParameter) ApplyRemovalPolicy(policy awscdk.RemovalPolicy) {
	if err := s.validateApplyRemovalPolicyParameters(policy); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		s,
		"applyRemovalPolicy",
		[]interface{}{policy},
	)
}

func (s *jsiiProxy_StringListParameter) GeneratePhysicalName() *string {
	var returns *string

	_jsii_.Invoke(
		s,
		"generatePhysicalName",
		nil, // no parameters
		&returns,
	)

	return returns
}

func (s *jsiiProxy_StringListParameter) GetResourceArnAttribute(arnAttr *string, arnComponents *awscdk.ArnComponents) *string {
	if err := s.validateGetResourceArnAttributeParameters(arnAttr, arnComponents); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		s,
		"getResourceArnAttribute",
		[]interface{}{arnAttr, arnComponents},
		&returns,
	)

	return returns
}

func (s *jsiiProxy_StringListParameter) GetResourceNameAttribute(nameAttr *string) *string {
	if err := s.validateGetResourceNameAttributeParameters(nameAttr); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		s,
		"getResourceNameAttribute",
		[]interface{}{nameAttr},
		&returns,
	)

	return returns
}

func (s *jsiiProxy_StringListParameter) GrantRead(grantee awsiam.IGrantable) awsiam.Grant {
	if err := s.validateGrantReadParameters(grantee); err != nil {
		panic(err)
	}
	var returns awsiam.Grant

	_jsii_.Invoke(
		s,
		"grantRead",
		[]interface{}{grantee},
		&returns,
	)

	return returns
}

func (s *jsiiProxy_StringListParameter) GrantWrite(grantee awsiam.IGrantable) awsiam.Grant {
	if err := s.validateGrantWriteParameters(grantee); err != nil {
		panic(err)
	}
	var returns awsiam.Grant

	_jsii_.Invoke(
		s,
		"grantWrite",
		[]interface{}{grantee},
		&returns,
	)

	return returns
}

func (s *jsiiProxy_StringListParameter) ToString() *string {
	var returns *string

	_jsii_.Invoke(
		s,
		"toString",
		nil, // no parameters
		&returns,
	)

	return returns
}

