package awscognito

import (
	_init_ "github.com/aws/aws-cdk-go/awscdk/v2/jsii"
	_jsii_ "github.com/aws/jsii-runtime-go/runtime"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscognito/internal"
	"github.com/aws/constructs-go/constructs/v10"
)

// Represents an identity provider that integrates with Google.
//
// Example:
//   userpool := cognito.NewUserPool(this, jsii.String("Pool"))
//   secret := secretsmanager.Secret_FromSecretAttributes(this, jsii.String("CognitoClientSecret"), &SecretAttributes{
//   	SecretCompleteArn: jsii.String("arn:aws:secretsmanager:xxx:xxx:secret:xxx-xxx"),
//   }).SecretValue
//
//   provider := cognito.NewUserPoolIdentityProviderGoogle(this, jsii.String("Google"), &UserPoolIdentityProviderGoogleProps{
//   	ClientId: jsii.String("amzn-client-id"),
//   	ClientSecretValue: secret,
//   	UserPool: userpool,
//   })
//
type UserPoolIdentityProviderGoogle interface {
	awscdk.Resource
	IUserPoolIdentityProvider
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
	// Returns a string-encoded token that resolves to the physical name that should be passed to the CloudFormation resource.
	//
	// This value will resolve to one of the following:
	// - a concrete value (e.g. `"my-awesome-bucket"`)
	// - `undefined`, when a name should be generated by CloudFormation
	// - a concrete name generated automatically during synthesis, in
	//   cross-environment scenarios.
	PhysicalName() *string
	// The primary identifier of this identity provider.
	ProviderName() *string
	// The stack in which this resource is defined.
	Stack() awscdk.Stack
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
	ConfigureAttributeMapping() interface{}
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

// The jsii proxy struct for UserPoolIdentityProviderGoogle
type jsiiProxy_UserPoolIdentityProviderGoogle struct {
	internal.Type__awscdkResource
	jsiiProxy_IUserPoolIdentityProvider
}

func (j *jsiiProxy_UserPoolIdentityProviderGoogle) Env() *awscdk.ResourceEnvironment {
	var returns *awscdk.ResourceEnvironment
	_jsii_.Get(
		j,
		"env",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_UserPoolIdentityProviderGoogle) Node() constructs.Node {
	var returns constructs.Node
	_jsii_.Get(
		j,
		"node",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_UserPoolIdentityProviderGoogle) PhysicalName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"physicalName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_UserPoolIdentityProviderGoogle) ProviderName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"providerName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_UserPoolIdentityProviderGoogle) Stack() awscdk.Stack {
	var returns awscdk.Stack
	_jsii_.Get(
		j,
		"stack",
		&returns,
	)
	return returns
}


func NewUserPoolIdentityProviderGoogle(scope constructs.Construct, id *string, props *UserPoolIdentityProviderGoogleProps) UserPoolIdentityProviderGoogle {
	_init_.Initialize()

	if err := validateNewUserPoolIdentityProviderGoogleParameters(scope, id, props); err != nil {
		panic(err)
	}
	j := jsiiProxy_UserPoolIdentityProviderGoogle{}

	_jsii_.Create(
		"aws-cdk-lib.aws_cognito.UserPoolIdentityProviderGoogle",
		[]interface{}{scope, id, props},
		&j,
	)

	return &j
}

func NewUserPoolIdentityProviderGoogle_Override(u UserPoolIdentityProviderGoogle, scope constructs.Construct, id *string, props *UserPoolIdentityProviderGoogleProps) {
	_init_.Initialize()

	_jsii_.Create(
		"aws-cdk-lib.aws_cognito.UserPoolIdentityProviderGoogle",
		[]interface{}{scope, id, props},
		u,
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
func UserPoolIdentityProviderGoogle_IsConstruct(x interface{}) *bool {
	_init_.Initialize()

	if err := validateUserPoolIdentityProviderGoogle_IsConstructParameters(x); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_cognito.UserPoolIdentityProviderGoogle",
		"isConstruct",
		[]interface{}{x},
		&returns,
	)

	return returns
}

// Returns true if the construct was created by CDK, and false otherwise.
func UserPoolIdentityProviderGoogle_IsOwnedResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateUserPoolIdentityProviderGoogle_IsOwnedResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_cognito.UserPoolIdentityProviderGoogle",
		"isOwnedResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

// Check whether the given construct is a Resource.
func UserPoolIdentityProviderGoogle_IsResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateUserPoolIdentityProviderGoogle_IsResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_cognito.UserPoolIdentityProviderGoogle",
		"isResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

func (u *jsiiProxy_UserPoolIdentityProviderGoogle) ApplyRemovalPolicy(policy awscdk.RemovalPolicy) {
	if err := u.validateApplyRemovalPolicyParameters(policy); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		u,
		"applyRemovalPolicy",
		[]interface{}{policy},
	)
}

func (u *jsiiProxy_UserPoolIdentityProviderGoogle) ConfigureAttributeMapping() interface{} {
	var returns interface{}

	_jsii_.Invoke(
		u,
		"configureAttributeMapping",
		nil, // no parameters
		&returns,
	)

	return returns
}

func (u *jsiiProxy_UserPoolIdentityProviderGoogle) GeneratePhysicalName() *string {
	var returns *string

	_jsii_.Invoke(
		u,
		"generatePhysicalName",
		nil, // no parameters
		&returns,
	)

	return returns
}

func (u *jsiiProxy_UserPoolIdentityProviderGoogle) GetResourceArnAttribute(arnAttr *string, arnComponents *awscdk.ArnComponents) *string {
	if err := u.validateGetResourceArnAttributeParameters(arnAttr, arnComponents); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		u,
		"getResourceArnAttribute",
		[]interface{}{arnAttr, arnComponents},
		&returns,
	)

	return returns
}

func (u *jsiiProxy_UserPoolIdentityProviderGoogle) GetResourceNameAttribute(nameAttr *string) *string {
	if err := u.validateGetResourceNameAttributeParameters(nameAttr); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		u,
		"getResourceNameAttribute",
		[]interface{}{nameAttr},
		&returns,
	)

	return returns
}

func (u *jsiiProxy_UserPoolIdentityProviderGoogle) ToString() *string {
	var returns *string

	_jsii_.Invoke(
		u,
		"toString",
		nil, // no parameters
		&returns,
	)

	return returns
}

