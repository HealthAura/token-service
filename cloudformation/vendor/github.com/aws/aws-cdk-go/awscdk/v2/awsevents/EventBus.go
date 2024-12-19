package awsevents

import (
	_init_ "github.com/aws/aws-cdk-go/awscdk/v2/jsii"
	_jsii_ "github.com/aws/jsii-runtime-go/runtime"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsevents/internal"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/constructs-go/constructs/v10"
)

// Define an EventBridge EventBus.
//
// Example:
//   bus := events.NewEventBus(this, jsii.String("bus"), &EventBusProps{
//   	EventBusName: jsii.String("MyCustomEventBus"),
//   	Description: jsii.String("MyCustomEventBus"),
//   })
//
//   bus.archive(jsii.String("MyArchive"), &BaseArchiveProps{
//   	ArchiveName: jsii.String("MyCustomEventBusArchive"),
//   	Description: jsii.String("MyCustomerEventBus Archive"),
//   	EventPattern: &EventPattern{
//   		Account: []*string{
//   			awscdk.*stack_Of(this).Account,
//   		},
//   	},
//   	Retention: awscdk.Duration_Days(jsii.Number(365)),
//   })
//
type EventBus interface {
	awscdk.Resource
	IEventBus
	// The environment this resource belongs to.
	//
	// For resources that are created and managed by the CDK
	// (generally, those created by creating new class instances like Role, Bucket, etc.),
	// this is always the same as the environment of the stack they belong to;
	// however, for imported resources
	// (those obtained from static methods like fromRoleArn, fromBucketName, etc.),
	// that might be different than the stack they were imported into.
	Env() *awscdk.ResourceEnvironment
	// The ARN of the event bus, such as: arn:aws:events:us-east-2:123456789012:event-bus/aws.partner/PartnerName/acct1/repo1.
	EventBusArn() *string
	// The physical ID of this event bus resource.
	EventBusName() *string
	// The policy for the event bus in JSON form.
	EventBusPolicy() *string
	// The name of the partner event source.
	EventSourceName() *string
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
	// Adds a statement to the IAM resource policy associated with this event bus.
	AddToResourcePolicy(statement awsiam.PolicyStatement) *awsiam.AddToResourcePolicyResult
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
	// Create an EventBridge archive to send events to.
	//
	// When you create an archive, incoming events might not immediately start being sent to the archive.
	// Allow a short period of time for changes to take effect.
	Archive(id *string, props *BaseArchiveProps) Archive
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
	// Grants an IAM Principal to send custom events to the eventBus so that they can be matched to rules.
	GrantPutEventsTo(grantee awsiam.IGrantable) awsiam.Grant
	// Returns a string representation of this construct.
	ToString() *string
}

// The jsii proxy struct for EventBus
type jsiiProxy_EventBus struct {
	internal.Type__awscdkResource
	jsiiProxy_IEventBus
}

func (j *jsiiProxy_EventBus) Env() *awscdk.ResourceEnvironment {
	var returns *awscdk.ResourceEnvironment
	_jsii_.Get(
		j,
		"env",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_EventBus) EventBusArn() *string {
	var returns *string
	_jsii_.Get(
		j,
		"eventBusArn",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_EventBus) EventBusName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"eventBusName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_EventBus) EventBusPolicy() *string {
	var returns *string
	_jsii_.Get(
		j,
		"eventBusPolicy",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_EventBus) EventSourceName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"eventSourceName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_EventBus) Node() constructs.Node {
	var returns constructs.Node
	_jsii_.Get(
		j,
		"node",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_EventBus) PhysicalName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"physicalName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_EventBus) Stack() awscdk.Stack {
	var returns awscdk.Stack
	_jsii_.Get(
		j,
		"stack",
		&returns,
	)
	return returns
}


func NewEventBus(scope constructs.Construct, id *string, props *EventBusProps) EventBus {
	_init_.Initialize()

	if err := validateNewEventBusParameters(scope, id, props); err != nil {
		panic(err)
	}
	j := jsiiProxy_EventBus{}

	_jsii_.Create(
		"aws-cdk-lib.aws_events.EventBus",
		[]interface{}{scope, id, props},
		&j,
	)

	return &j
}

func NewEventBus_Override(e EventBus, scope constructs.Construct, id *string, props *EventBusProps) {
	_init_.Initialize()

	_jsii_.Create(
		"aws-cdk-lib.aws_events.EventBus",
		[]interface{}{scope, id, props},
		e,
	)
}

// Import an existing event bus resource.
func EventBus_FromEventBusArn(scope constructs.Construct, id *string, eventBusArn *string) IEventBus {
	_init_.Initialize()

	if err := validateEventBus_FromEventBusArnParameters(scope, id, eventBusArn); err != nil {
		panic(err)
	}
	var returns IEventBus

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_events.EventBus",
		"fromEventBusArn",
		[]interface{}{scope, id, eventBusArn},
		&returns,
	)

	return returns
}

// Import an existing event bus resource.
func EventBus_FromEventBusAttributes(scope constructs.Construct, id *string, attrs *EventBusAttributes) IEventBus {
	_init_.Initialize()

	if err := validateEventBus_FromEventBusAttributesParameters(scope, id, attrs); err != nil {
		panic(err)
	}
	var returns IEventBus

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_events.EventBus",
		"fromEventBusAttributes",
		[]interface{}{scope, id, attrs},
		&returns,
	)

	return returns
}

// Import an existing event bus resource.
func EventBus_FromEventBusName(scope constructs.Construct, id *string, eventBusName *string) IEventBus {
	_init_.Initialize()

	if err := validateEventBus_FromEventBusNameParameters(scope, id, eventBusName); err != nil {
		panic(err)
	}
	var returns IEventBus

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_events.EventBus",
		"fromEventBusName",
		[]interface{}{scope, id, eventBusName},
		&returns,
	)

	return returns
}

// Permits an IAM Principal to send custom events to EventBridge so that they can be matched to rules.
func EventBus_GrantAllPutEvents(grantee awsiam.IGrantable) awsiam.Grant {
	_init_.Initialize()

	if err := validateEventBus_GrantAllPutEventsParameters(grantee); err != nil {
		panic(err)
	}
	var returns awsiam.Grant

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_events.EventBus",
		"grantAllPutEvents",
		[]interface{}{grantee},
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
func EventBus_IsConstruct(x interface{}) *bool {
	_init_.Initialize()

	if err := validateEventBus_IsConstructParameters(x); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_events.EventBus",
		"isConstruct",
		[]interface{}{x},
		&returns,
	)

	return returns
}

// Returns true if the construct was created by CDK, and false otherwise.
func EventBus_IsOwnedResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateEventBus_IsOwnedResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_events.EventBus",
		"isOwnedResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

// Check whether the given construct is a Resource.
func EventBus_IsResource(construct constructs.IConstruct) *bool {
	_init_.Initialize()

	if err := validateEventBus_IsResourceParameters(construct); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_events.EventBus",
		"isResource",
		[]interface{}{construct},
		&returns,
	)

	return returns
}

func (e *jsiiProxy_EventBus) AddToResourcePolicy(statement awsiam.PolicyStatement) *awsiam.AddToResourcePolicyResult {
	if err := e.validateAddToResourcePolicyParameters(statement); err != nil {
		panic(err)
	}
	var returns *awsiam.AddToResourcePolicyResult

	_jsii_.Invoke(
		e,
		"addToResourcePolicy",
		[]interface{}{statement},
		&returns,
	)

	return returns
}

func (e *jsiiProxy_EventBus) ApplyRemovalPolicy(policy awscdk.RemovalPolicy) {
	if err := e.validateApplyRemovalPolicyParameters(policy); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		e,
		"applyRemovalPolicy",
		[]interface{}{policy},
	)
}

func (e *jsiiProxy_EventBus) Archive(id *string, props *BaseArchiveProps) Archive {
	if err := e.validateArchiveParameters(id, props); err != nil {
		panic(err)
	}
	var returns Archive

	_jsii_.Invoke(
		e,
		"archive",
		[]interface{}{id, props},
		&returns,
	)

	return returns
}

func (e *jsiiProxy_EventBus) GeneratePhysicalName() *string {
	var returns *string

	_jsii_.Invoke(
		e,
		"generatePhysicalName",
		nil, // no parameters
		&returns,
	)

	return returns
}

func (e *jsiiProxy_EventBus) GetResourceArnAttribute(arnAttr *string, arnComponents *awscdk.ArnComponents) *string {
	if err := e.validateGetResourceArnAttributeParameters(arnAttr, arnComponents); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		e,
		"getResourceArnAttribute",
		[]interface{}{arnAttr, arnComponents},
		&returns,
	)

	return returns
}

func (e *jsiiProxy_EventBus) GetResourceNameAttribute(nameAttr *string) *string {
	if err := e.validateGetResourceNameAttributeParameters(nameAttr); err != nil {
		panic(err)
	}
	var returns *string

	_jsii_.Invoke(
		e,
		"getResourceNameAttribute",
		[]interface{}{nameAttr},
		&returns,
	)

	return returns
}

func (e *jsiiProxy_EventBus) GrantPutEventsTo(grantee awsiam.IGrantable) awsiam.Grant {
	if err := e.validateGrantPutEventsToParameters(grantee); err != nil {
		panic(err)
	}
	var returns awsiam.Grant

	_jsii_.Invoke(
		e,
		"grantPutEventsTo",
		[]interface{}{grantee},
		&returns,
	)

	return returns
}

func (e *jsiiProxy_EventBus) ToString() *string {
	var returns *string

	_jsii_.Invoke(
		e,
		"toString",
		nil, // no parameters
		&returns,
	)

	return returns
}

