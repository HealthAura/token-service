package awslambda

import (
	_init_ "github.com/aws/aws-cdk-go/awscdk/v2/jsii"
	_jsii_ "github.com/aws/jsii-runtime-go/runtime"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudwatch"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/constructs-go/constructs/v10"
)

// Tag the current state of a Function with a Version number.
//
// Avoid using this resource directly. If you need a Version object, use
// `function.currentVersion` instead. That will add a Version object to your
// template, and make sure the Version is invalidated whenever the Function
// object changes. If you use the `Version` resource directly, you are
// responsible for making sure it is invalidated (by changing its
// logical ID) whenever necessary.
//
// Version resources can then be used in `Alias` resources to refer to a
// particular deployment of a Lambda.
//
// If you want to ensure that you're associating the right version with
// the right deployment, specify the `codeSha256` property while
// creating the `Version.
//
// Example:
//   lambdaCode := lambda.Code_FromCfnParameters()
//   func := lambda.NewFunction(this, jsii.String("Lambda"), &FunctionProps{
//   	Code: lambdaCode,
//   	Handler: jsii.String("index.handler"),
//   	Runtime: lambda.Runtime_NODEJS_LATEST(),
//   })
//   // used to make sure each CDK synthesis produces a different Version
//   version := func.currentVersion
//   alias := lambda.NewAlias(this, jsii.String("LambdaAlias"), &AliasProps{
//   	AliasName: jsii.String("Prod"),
//   	Version: Version,
//   })
//
//   codedeploy.NewLambdaDeploymentGroup(this, jsii.String("DeploymentGroup"), &LambdaDeploymentGroupProps{
//   	Alias: Alias,
//   	DeploymentConfig: codedeploy.LambdaDeploymentConfig_LINEAR_10PERCENT_EVERY_1MINUTE(),
//   })
//
type Version interface {
	QualifiedFunctionBase
	IVersion
	// The architecture of this Lambda Function.
	Architecture() Architecture
	// Whether the addPermission() call adds any permissions.
	//
	// True for new Lambdas, false for version $LATEST and imported Lambdas
	// from different accounts.
	CanCreatePermissions() *bool
	// Access the Connections object.
	//
	// Will fail if not a VPC-enabled Lambda Function.
	Connections() awsec2.Connections
	// The ARN of the version for Lambda@Edge.
	EdgeArn() *string
	// The environment this resource belongs to.
	//
	// For resources that are created and managed by the CDK
	// (generally, those created by creating new class instances like Role, Bucket, etc.),
	// this is always the same as the environment of the stack they belong to;
	// however, for imported resources
	// (those obtained from static methods like fromRoleArn, fromBucketName, etc.),
	// that might be different than the stack they were imported into.
	Env() *awscdk.ResourceEnvironment
	// The ARN fo the function.
	FunctionArn() *string
	// The name of the function.
	FunctionName() *string
	// The principal this Lambda Function is running as.
	GrantPrincipal() awsiam.IPrincipal
	// Whether or not this Lambda function was bound to a VPC.
	//
	// If this is is `false`, trying to access the `connections` object will fail.
	IsBoundToVpc() *bool
	// The underlying `IFunction`.
	Lambda() IFunction
	// The `$LATEST` version of this function.
	//
	// Note that this is reference to a non-specific AWS Lambda version, which
	// means the function this version refers to can return different results in
	// different invocations.
	//
	// To obtain a reference to an explicit version which references the current
	// function configuration, use `lambdaFunction.currentVersion` instead.
	LatestVersion() IVersion
	// The tree node.
	Node() constructs.Node
	// The construct node where permissions are attached.
	PermissionsNode() constructs.Node
	// Returns a string-encoded token that resolves to the physical name that should be passed to the CloudFormation resource.
	//
	// This value will resolve to one of the following:
	// - a concrete value (e.g. `"my-awesome-bucket"`)
	// - `undefined`, when a name should be generated by CloudFormation
	// - a concrete name generated automatically during synthesis, in
	//   cross-environment scenarios.
	PhysicalName() *string
	// The qualifier of the version or alias of this function.
	//
	// A qualifier is the identifier that's appended to a version or alias ARN.
	Qualifier() *string
	// The ARN(s) to put into the resource field of the generated IAM policy for grantInvoke().
	ResourceArnsForGrantInvoke() *[]*string
	// The IAM role associated with this function.
	//
	// Undefined if the function was imported without a role.
	Role() awsiam.IRole
	// The stack in which this resource is defined.
	Stack() awscdk.Stack
	// The most recently deployed version of this function.
	Version() *string
	// Defines an alias for this version.
	// Deprecated: Calling `addAlias` on a `Version` object will cause the Alias to be replaced on every function update. Call `function.addAlias()` or `new Alias()` instead.
	AddAlias(aliasName *string, options *AliasOptions) Alias
	// Adds an event source to this function.
	//
	// Event sources are implemented in the aws-cdk-lib/aws-lambda-event-sources module.
	//
	// The following example adds an SQS Queue as an event source:
	// ```
	// import { SqsEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';
	// myFunction.addEventSource(new SqsEventSource(myQueue));
	// ```.
	AddEventSource(source IEventSource)
	// Adds an event source that maps to this AWS Lambda function.
	AddEventSourceMapping(id *string, options *EventSourceMappingOptions) EventSourceMapping
	// Adds a url to this lambda function.
	AddFunctionUrl(options *FunctionUrlOptions) FunctionUrl
	// Adds a permission to the Lambda resource policy.
	// See: Permission for details.
	//
	AddPermission(id *string, permission *Permission)
	// Adds a statement to the IAM role assumed by the instance.
	AddToRolePolicy(statement awsiam.PolicyStatement)
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
	// Configures options for asynchronous invocation.
	ConfigureAsyncInvoke(options *EventInvokeConfigOptions)
	// A warning will be added to functions under the following conditions: - permissions that include `lambda:InvokeFunction` are added to the unqualified function.
	//
	// - function.currentVersion is invoked before or after the permission is created.
	//
	// This applies only to permissions on Lambda functions, not versions or aliases.
	// This function is overridden as a noOp for QualifiedFunctionBase.
	ConsiderWarningOnInvokeFunctionPermissions(_scope constructs.Construct, _action *string)
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
	// Grant the given identity permissions to invoke this Lambda.
	GrantInvoke(grantee awsiam.IGrantable) awsiam.Grant
	// Grant multiple principals the ability to invoke this Lambda via CompositePrincipal.
	GrantInvokeCompositePrincipal(compositePrincipal awsiam.CompositePrincipal) *[]awsiam.Grant
	// Grant the given identity permissions to invoke the $LATEST version or unqualified version of this Lambda.
	GrantInvokeLatestVersion(grantee awsiam.IGrantable) awsiam.Grant
	// Grant the given identity permissions to invoke this Lambda Function URL.
	GrantInvokeUrl(grantee awsiam.IGrantable) awsiam.Grant
	// Grant the given identity permissions to invoke the given version of this Lambda.
	GrantInvokeVersion(grantee awsiam.IGrantable, version IVersion) awsiam.Grant
	// Return the given named metric for this Function.
	Metric(metricName *string, props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// How long execution of this Lambda takes.
	//
	// Average over 5 minutes.
	MetricDuration(props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// How many invocations of this Lambda fail.
	//
	// Sum over 5 minutes.
	MetricErrors(props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// How often this Lambda is invoked.
	//
	// Sum over 5 minutes.
	MetricInvocations(props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// How often this Lambda is throttled.
	//
	// Sum over 5 minutes.
	MetricThrottles(props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// Returns a string representation of this construct.
	ToString() *string
	WarnInvokeFunctionPermissions(scope constructs.Construct)
}

// The jsii proxy struct for Version
type jsiiProxy_Version struct {
	jsiiProxy_QualifiedFunctionBase
	jsiiProxy_IVersion
}

func (j *jsiiProxy_Version) Architecture() Architecture {
	var returns Architecture
	_jsii_.Get(
		j,
		"architecture",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) CanCreatePermissions() *bool {
	var returns *bool
	_jsii_.Get(
		j,
		"canCreatePermissions",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) Connections() awsec2.Connections {
	var returns awsec2.Connections
	_jsii_.Get(
		j,
		"connections",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) EdgeArn() *string {
	var returns *string
	_jsii_.Get(
		j,
		"edgeArn",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) Env() *awscdk.ResourceEnvironment {
	var returns *awscdk.ResourceEnvironment
	_jsii_.Get(
		j,
		"env",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) FunctionArn() *string {
	var returns *string
	_jsii_.Get(
		j,
		"functionArn",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) FunctionName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"functionName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) GrantPrincipal() awsiam.IPrincipal {
	var returns awsiam.IPrincipal
	_jsii_.Get(
		j,
		"grantPrincipal",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) IsBoundToVpc() *bool {
	var returns *bool
	_jsii_.Get(
		j,
		"isBoundToVpc",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) Lambda() IFunction {
	var returns IFunction
	_jsii_.Get(
		j,
		"lambda",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) LatestVersion() IVersion {
	var returns IVersion
	_jsii_.Get(
		j,
		"latestVersion",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) Node() constructs.Node {
	var returns constructs.Node
	_jsii_.Get(
		j,
		"node",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) PermissionsNode() constructs.Node {
	var returns constructs.Node
	_jsii_.Get(
		j,
		"permissionsNode",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) PhysicalName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"physicalName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) Qualifier() *string {
	var returns *string
	_jsii_.Get(
		j,
		"qualifier",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) ResourceArnsForGrantInvoke() *[]*string {
	var returns *[]*string
	_jsii_.Get(
		j,
		"resourceArnsForGrantInvoke",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) Role() awsiam.IRole {
	var returns awsiam.IRole
	_jsii_.Get(
		j,
		"role",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) Stack() awscdk.Stack {
	var returns awscdk.Stack
	_jsii_.Get(
		j,
		"stack",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_Version) Version() *string {
	var returns *string
	_jsii_.Get(
		j,
		"version",
		&returns,
	)
	return returns
}


func NewVersion(scope constructs.Construct, id *string, props *VersionProps) Version {
	_init_.Initialize()

	if err := validateNewVersionParameters(scope, id, props); err != nil {
		panic(err)
	}
	j := jsiiProxy_Version{}

	_jsii_.Create(
		"aws-cdk-lib.aws_lambda.Version",
		[]interface{}{scope, id, props},
		&j,
	)

	return &j
}

func NewVersion_Override(v Version, scope constructs.Construct, id *string, props *VersionProps) {
	_init_.Initialize()

	_jsii_.Create(
		"aws-cdk-lib.aws_lambda.Version",
		[]interface{}{scope, id, props},
		v,
	)
}

// Construct a Version object from a Version ARN.
func Version_FromVersionArn(scope constructs.Construct, id *string, versionArn *string) IVersion {
	_init_.Initialize()

	if err := validateVersion_FromVersionArnParameters(scope, id, versionArn); err != nil {
		panic(err)
	}
	var returns IVersion

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_lambda.Version",
		"fromVersionArn",
		[]interface{}{scope, id, versionArn},
		&returns,
	)

	return returns
}

func Version_FromVersionAttributes(scope constructs.Construct, id *string, attrs *VersionAttributes) IVersion {
	_init_.Initialize()

	if err := validateVersion_FromVersionAttributesParameters(scope, id, attrs); err != nil {
		panic(err)
	}
	var returns IVersion

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_lambda.Version",
		"fromVersionAttributes",
		[]interface{}{scope, id, attrs},
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
func Version_IsConstruct(x interface{}) *bool {
	_init_.Initialize()

	if err := validateVersion_IsConstructParameters(x); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_lambda.Version",
		"isConstruct",
		[]interface{}{x},
		&returns,
	)

	return returns
}

// Returns true if the construct was created by CDK, and false otherwise.
func Version_IsOwnedResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateVersion_IsOwnedResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_lambda.Version",
		"isOwnedResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

// Check whether the given construct is a Resource.
func Version_IsResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateVersion_IsResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_lambda.Version",
		"isResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) AddAlias(aliasName *string, options *AliasOptions) Alias {
	if err := v.validateAddAliasParameters(aliasName, options); err != nil {
		panic(err)
	}
	var returns Alias

	_jsii_.Invoke(
		v,
		"addAlias",
		[]interface{}{aliasName, options},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) AddEventSource(source IEventSource) {
	if err := v.validateAddEventSourceParameters(source); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		v,
		"addEventSource",
		[]interface{}{source},
	)
}

func (v *jsiiProxy_Version) AddEventSourceMapping(id *string, options *EventSourceMappingOptions) EventSourceMapping {
	if err := v.validateAddEventSourceMappingParameters(id, options); err != nil {
		panic(err)
	}
	var returns EventSourceMapping

	_jsii_.Invoke(
		v,
		"addEventSourceMapping",
		[]interface{}{id, options},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) AddFunctionUrl(options *FunctionUrlOptions) FunctionUrl {
	if err := v.validateAddFunctionUrlParameters(options); err != nil {
		panic(err)
	}
	var returns FunctionUrl

	_jsii_.Invoke(
		v,
		"addFunctionUrl",
		[]interface{}{options},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) AddPermission(id *string, permission *Permission) {
	if err := v.validateAddPermissionParameters(id, permission); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		v,
		"addPermission",
		[]interface{}{id, permission},
	)
}

func (v *jsiiProxy_Version) AddToRolePolicy(statement awsiam.PolicyStatement) {
	if err := v.validateAddToRolePolicyParameters(statement); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		v,
		"addToRolePolicy",
		[]interface{}{statement},
	)
}

func (v *jsiiProxy_Version) ApplyRemovalPolicy(policy awscdk.RemovalPolicy) {
	if err := v.validateApplyRemovalPolicyParameters(policy); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		v,
		"applyRemovalPolicy",
		[]interface{}{policy},
	)
}

func (v *jsiiProxy_Version) ConfigureAsyncInvoke(options *EventInvokeConfigOptions) {
	if err := v.validateConfigureAsyncInvokeParameters(options); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		v,
		"configureAsyncInvoke",
		[]interface{}{options},
	)
}

func (v *jsiiProxy_Version) ConsiderWarningOnInvokeFunctionPermissions(_scope constructs.Construct, _action *string) {
	if err := v.validateConsiderWarningOnInvokeFunctionPermissionsParameters(_scope, _action); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		v,
		"considerWarningOnInvokeFunctionPermissions",
		[]interface{}{_scope, _action},
	)
}

func (v *jsiiProxy_Version) GeneratePhysicalName() *string {
	var returns *string

	_jsii_.Invoke(
		v,
		"generatePhysicalName",
		nil, // no parameters
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) GetResourceArnAttribute(arnAttr *string, arnComponents *awscdk.ArnComponents) *string {
	if err := v.validateGetResourceArnAttributeParameters(arnAttr, arnComponents); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		v,
		"getResourceArnAttribute",
		[]interface{}{arnAttr, arnComponents},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) GetResourceNameAttribute(nameAttr *string) *string {
	if err := v.validateGetResourceNameAttributeParameters(nameAttr); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		v,
		"getResourceNameAttribute",
		[]interface{}{nameAttr},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) GrantInvoke(grantee awsiam.IGrantable) awsiam.Grant {
	if err := v.validateGrantInvokeParameters(grantee); err != nil {
		panic(err)
	}
	var returns awsiam.Grant

	_jsii_.Invoke(
		v,
		"grantInvoke",
		[]interface{}{grantee},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) GrantInvokeCompositePrincipal(compositePrincipal awsiam.CompositePrincipal) *[]awsiam.Grant {
	if err := v.validateGrantInvokeCompositePrincipalParameters(compositePrincipal); err != nil {
		panic(err)
	}
	var returns *[]awsiam.Grant

	_jsii_.Invoke(
		v,
		"grantInvokeCompositePrincipal",
		[]interface{}{compositePrincipal},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) GrantInvokeLatestVersion(grantee awsiam.IGrantable) awsiam.Grant {
	if err := v.validateGrantInvokeLatestVersionParameters(grantee); err != nil {
		panic(err)
	}
	var returns awsiam.Grant

	_jsii_.Invoke(
		v,
		"grantInvokeLatestVersion",
		[]interface{}{grantee},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) GrantInvokeUrl(grantee awsiam.IGrantable) awsiam.Grant {
	if err := v.validateGrantInvokeUrlParameters(grantee); err != nil {
		panic(err)
	}
	var returns awsiam.Grant

	_jsii_.Invoke(
		v,
		"grantInvokeUrl",
		[]interface{}{grantee},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) GrantInvokeVersion(grantee awsiam.IGrantable, version IVersion) awsiam.Grant {
	if err := v.validateGrantInvokeVersionParameters(grantee, version); err != nil {
		panic(err)
	}
	var returns awsiam.Grant

	_jsii_.Invoke(
		v,
		"grantInvokeVersion",
		[]interface{}{grantee, version},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) Metric(metricName *string, props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := v.validateMetricParameters(metricName, props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		v,
		"metric",
		[]interface{}{metricName, props},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) MetricDuration(props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := v.validateMetricDurationParameters(props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		v,
		"metricDuration",
		[]interface{}{props},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) MetricErrors(props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := v.validateMetricErrorsParameters(props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		v,
		"metricErrors",
		[]interface{}{props},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) MetricInvocations(props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := v.validateMetricInvocationsParameters(props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		v,
		"metricInvocations",
		[]interface{}{props},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) MetricThrottles(props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := v.validateMetricThrottlesParameters(props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		v,
		"metricThrottles",
		[]interface{}{props},
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) ToString() *string {
	var returns *string

	_jsii_.Invoke(
		v,
		"toString",
		nil, // no parameters
		&returns,
	)

	return returns
}

func (v *jsiiProxy_Version) WarnInvokeFunctionPermissions(scope constructs.Construct) {
	if err := v.validateWarnInvokeFunctionPermissionsParameters(scope); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		v,
		"warnInvokeFunctionPermissions",
		[]interface{}{scope},
	)
}

