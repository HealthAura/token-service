package awselasticloadbalancingv2

import (
	_init_ "github.com/aws/aws-cdk-go/awscdk/v2/jsii"
	_jsii_ "github.com/aws/jsii-runtime-go/runtime"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudwatch"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/constructs-go/constructs/v10"
)

// Define an Application Target Group.
//
// Example:
//   var alb applicationLoadBalancer
//
//   listener := alb.AddListener(jsii.String("Listener"), &BaseApplicationListenerProps{
//   	Port: jsii.Number(80),
//   })
//   targetGroup := listener.AddTargets(jsii.String("Fleet"), &AddApplicationTargetsProps{
//   	Port: jsii.Number(80),
//   })
//
//   deploymentGroup := codedeploy.NewServerDeploymentGroup(this, jsii.String("DeploymentGroup"), &ServerDeploymentGroupProps{
//   	LoadBalancer: codedeploy.LoadBalancer_Application(targetGroup),
//   })
//
type ApplicationTargetGroup interface {
	TargetGroupBase
	IApplicationTargetGroup
	// Default port configured for members of this target group.
	DefaultPort() *float64
	// Full name of first load balancer.
	FirstLoadBalancerFullName() *string
	// Health check for the members of this target group.
	HealthCheck() *HealthCheck
	SetHealthCheck(val *HealthCheck)
	// A token representing a list of ARNs of the load balancers that route traffic to this target group.
	LoadBalancerArns() *string
	// List of constructs that need to be depended on to ensure the TargetGroup is associated to a load balancer.
	LoadBalancerAttached() constructs.IDependable
	// Configurable dependable with all resources that lead to load balancer attachment.
	LoadBalancerAttachedDependencies() constructs.DependencyGroup
	// All metrics available for this target group.
	Metrics() IApplicationTargetGroupMetrics
	// The tree node.
	Node() constructs.Node
	// The ARN of the target group.
	TargetGroupArn() *string
	// The full name of the target group.
	TargetGroupFullName() *string
	// ARNs of load balancers load balancing to this TargetGroup.
	TargetGroupLoadBalancerArns() *[]*string
	// The name of the target group.
	TargetGroupName() *string
	// The types of the directly registered members of this target group.
	TargetType() TargetType
	SetTargetType(val TargetType)
	// Register the given load balancing target as part of this group.
	AddLoadBalancerTarget(props *LoadBalancerTargetProps)
	// Add a load balancing target to this target group.
	AddTarget(targets ...IApplicationLoadBalancerTarget)
	// Set/replace the target group's health check.
	ConfigureHealthCheck(healthCheck *HealthCheck)
	// Enable sticky routing via a cookie to members of this target group.
	//
	// Note: If the `cookieName` parameter is set, application-based stickiness will be applied,
	// otherwise it defaults to duration-based stickiness attributes (`lb_cookie`).
	// See: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/sticky-sessions.html
	//
	EnableCookieStickiness(duration awscdk.Duration, cookieName *string)
	// Return the given named metric for this Application Load Balancer Target Group.
	//
	// Returns the metric for this target group from the point of view of the first
	// load balancer load balancing to it. If you have multiple load balancers load
	// sending traffic to the same target group, you will have to override the dimensions
	// on this metric.
	// Default: Average over 5 minutes.
	//
	Metric(metricName *string, props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// The number of healthy hosts in the target group.
	// Default: Average over 5 minutes.
	//
	// Deprecated: Use ``ApplicationTargetGroup.metrics.healthyHostCount`` instead
	MetricHealthyHostCount(props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// The number of HTTP 2xx/3xx/4xx/5xx response codes generated by all targets in this target group.
	//
	// This does not include any response codes generated by the load balancer.
	// Default: Sum over 5 minutes.
	//
	// Deprecated: Use ``ApplicationTargetGroup.metrics.httpCodeTarget`` instead
	MetricHttpCodeTarget(code HttpCodeTarget, props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// The number of IPv6 requests received by the target group.
	// Default: Sum over 5 minutes.
	//
	// Deprecated: Use ``ApplicationTargetGroup.metrics.ipv6RequestCount`` instead
	MetricIpv6RequestCount(props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// The number of requests processed over IPv4 and IPv6.
	//
	// This count includes only the requests with a response generated by a target of the load balancer.
	// Default: Sum over 5 minutes.
	//
	// Deprecated: Use ``ApplicationTargetGroup.metrics.requestCount`` instead
	MetricRequestCount(props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// The average number of requests received by each target in a target group.
	//
	// The only valid statistic is Sum. Note that this represents the average not the sum.
	// Default: Sum over 5 minutes.
	//
	// Deprecated: Use `ApplicationTargetGroup.metrics.requestCountPerTarget` instead
	MetricRequestCountPerTarget(props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// The number of connections that were not successfully established between the load balancer and target.
	// Default: Sum over 5 minutes.
	//
	// Deprecated: Use ``ApplicationTargetGroup.metrics.targetConnectionErrorCount`` instead
	MetricTargetConnectionErrorCount(props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// The time elapsed, in seconds, after the request leaves the load balancer until a response from the target is received.
	// Default: Average over 5 minutes.
	//
	// Deprecated: Use ``ApplicationTargetGroup.metrics.targetResponseTime`` instead
	MetricTargetResponseTime(props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// The number of TLS connections initiated by the load balancer that did not establish a session with the target.
	//
	// Possible causes include a mismatch of ciphers or protocols.
	// Default: Sum over 5 minutes.
	//
	// Deprecated: Use ``ApplicationTargetGroup.metrics.tlsNegotiationErrorCount`` instead
	MetricTargetTLSNegotiationErrorCount(props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// The number of unhealthy hosts in the target group.
	// Default: Average over 5 minutes.
	//
	// Deprecated: Use ``ApplicationTargetGroup.metrics.unhealthyHostCount`` instead
	MetricUnhealthyHostCount(props *awscloudwatch.MetricOptions) awscloudwatch.Metric
	// Register a connectable as a member of this target group.
	//
	// Don't call this directly. It will be called by load balancing targets.
	RegisterConnectable(connectable awsec2.IConnectable, portRange awsec2.Port)
	// Register a listener that is load balancing to this target group.
	//
	// Don't call this directly. It will be called by listeners.
	RegisterListener(listener IApplicationListener, associatingConstruct constructs.IConstruct)
	// Set a non-standard attribute on the target group.
	// See: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html#target-group-attributes
	//
	SetAttribute(key *string, value *string)
	// Returns a string representation of this construct.
	ToString() *string
	ValidateHealthCheck() *[]*string
	ValidateTargetGroup() *[]*string
}

// The jsii proxy struct for ApplicationTargetGroup
type jsiiProxy_ApplicationTargetGroup struct {
	jsiiProxy_TargetGroupBase
	jsiiProxy_IApplicationTargetGroup
}

func (j *jsiiProxy_ApplicationTargetGroup) DefaultPort() *float64 {
	var returns *float64
	_jsii_.Get(
		j,
		"defaultPort",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_ApplicationTargetGroup) FirstLoadBalancerFullName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"firstLoadBalancerFullName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_ApplicationTargetGroup) HealthCheck() *HealthCheck {
	var returns *HealthCheck
	_jsii_.Get(
		j,
		"healthCheck",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_ApplicationTargetGroup) LoadBalancerArns() *string {
	var returns *string
	_jsii_.Get(
		j,
		"loadBalancerArns",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_ApplicationTargetGroup) LoadBalancerAttached() constructs.IDependable {
	var returns constructs.IDependable
	_jsii_.Get(
		j,
		"loadBalancerAttached",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_ApplicationTargetGroup) LoadBalancerAttachedDependencies() constructs.DependencyGroup {
	var returns constructs.DependencyGroup
	_jsii_.Get(
		j,
		"loadBalancerAttachedDependencies",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_ApplicationTargetGroup) Metrics() IApplicationTargetGroupMetrics {
	var returns IApplicationTargetGroupMetrics
	_jsii_.Get(
		j,
		"metrics",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_ApplicationTargetGroup) Node() constructs.Node {
	var returns constructs.Node
	_jsii_.Get(
		j,
		"node",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_ApplicationTargetGroup) TargetGroupArn() *string {
	var returns *string
	_jsii_.Get(
		j,
		"targetGroupArn",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_ApplicationTargetGroup) TargetGroupFullName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"targetGroupFullName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_ApplicationTargetGroup) TargetGroupLoadBalancerArns() *[]*string {
	var returns *[]*string
	_jsii_.Get(
		j,
		"targetGroupLoadBalancerArns",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_ApplicationTargetGroup) TargetGroupName() *string {
	var returns *string
	_jsii_.Get(
		j,
		"targetGroupName",
		&returns,
	)
	return returns
}

func (j *jsiiProxy_ApplicationTargetGroup) TargetType() TargetType {
	var returns TargetType
	_jsii_.Get(
		j,
		"targetType",
		&returns,
	)
	return returns
}


func NewApplicationTargetGroup(scope constructs.Construct, id *string, props *ApplicationTargetGroupProps) ApplicationTargetGroup {
	_init_.Initialize()

	if err := validateNewApplicationTargetGroupParameters(scope, id, props); err != nil {
		panic(err)
	}
	j := jsiiProxy_ApplicationTargetGroup{}

	_jsii_.Create(
		"aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationTargetGroup",
		[]interface{}{scope, id, props},
		&j,
	)

	return &j
}

func NewApplicationTargetGroup_Override(a ApplicationTargetGroup, scope constructs.Construct, id *string, props *ApplicationTargetGroupProps) {
	_init_.Initialize()

	_jsii_.Create(
		"aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationTargetGroup",
		[]interface{}{scope, id, props},
		a,
	)
}

func (j *jsiiProxy_ApplicationTargetGroup)SetHealthCheck(val *HealthCheck) {
	if err := j.validateSetHealthCheckParameters(val); err != nil {
		panic(err)
	}
	_jsii_.Set(
		j,
		"healthCheck",
		val,
	)
}

func (j *jsiiProxy_ApplicationTargetGroup)SetTargetType(val TargetType) {
	_jsii_.Set(
		j,
		"targetType",
		val,
	)
}

// Import an existing target group.
func ApplicationTargetGroup_FromTargetGroupAttributes(scope constructs.Construct, id *string, attrs *TargetGroupAttributes) IApplicationTargetGroup {
	_init_.Initialize()

	if err := validateApplicationTargetGroup_FromTargetGroupAttributesParameters(scope, id, attrs); err != nil {
		panic(err)
	}
	var returns IApplicationTargetGroup

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationTargetGroup",
		"fromTargetGroupAttributes",
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
func ApplicationTargetGroup_IsConstruct(x interface{}) *bool {
	_init_.Initialize()

	if err := validateApplicationTargetGroup_IsConstructParameters(x); err != nil {
		panic(err)
	}
	var returns *bool

	_jsii_.StaticInvoke(
		"aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationTargetGroup",
		"isConstruct",
		[]interface{}{x},
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) AddLoadBalancerTarget(props *LoadBalancerTargetProps) {
	if err := a.validateAddLoadBalancerTargetParameters(props); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		a,
		"addLoadBalancerTarget",
		[]interface{}{props},
	)
}

func (a *jsiiProxy_ApplicationTargetGroup) AddTarget(targets ...IApplicationLoadBalancerTarget) {
	args := []interface{}{}
	for _, a := range targets {
		args = append(args, a)
	}

	_jsii_.InvokeVoid(
		a,
		"addTarget",
		args,
	)
}

func (a *jsiiProxy_ApplicationTargetGroup) ConfigureHealthCheck(healthCheck *HealthCheck) {
	if err := a.validateConfigureHealthCheckParameters(healthCheck); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		a,
		"configureHealthCheck",
		[]interface{}{healthCheck},
	)
}

func (a *jsiiProxy_ApplicationTargetGroup) EnableCookieStickiness(duration awscdk.Duration, cookieName *string) {
	if err := a.validateEnableCookieStickinessParameters(duration); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		a,
		"enableCookieStickiness",
		[]interface{}{duration, cookieName},
	)
}

func (a *jsiiProxy_ApplicationTargetGroup) Metric(metricName *string, props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := a.validateMetricParameters(metricName, props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		a,
		"metric",
		[]interface{}{metricName, props},
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) MetricHealthyHostCount(props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := a.validateMetricHealthyHostCountParameters(props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		a,
		"metricHealthyHostCount",
		[]interface{}{props},
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) MetricHttpCodeTarget(code HttpCodeTarget, props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := a.validateMetricHttpCodeTargetParameters(code, props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		a,
		"metricHttpCodeTarget",
		[]interface{}{code, props},
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) MetricIpv6RequestCount(props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := a.validateMetricIpv6RequestCountParameters(props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		a,
		"metricIpv6RequestCount",
		[]interface{}{props},
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) MetricRequestCount(props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := a.validateMetricRequestCountParameters(props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		a,
		"metricRequestCount",
		[]interface{}{props},
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) MetricRequestCountPerTarget(props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := a.validateMetricRequestCountPerTargetParameters(props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		a,
		"metricRequestCountPerTarget",
		[]interface{}{props},
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) MetricTargetConnectionErrorCount(props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := a.validateMetricTargetConnectionErrorCountParameters(props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		a,
		"metricTargetConnectionErrorCount",
		[]interface{}{props},
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) MetricTargetResponseTime(props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := a.validateMetricTargetResponseTimeParameters(props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		a,
		"metricTargetResponseTime",
		[]interface{}{props},
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) MetricTargetTLSNegotiationErrorCount(props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := a.validateMetricTargetTLSNegotiationErrorCountParameters(props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		a,
		"metricTargetTLSNegotiationErrorCount",
		[]interface{}{props},
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) MetricUnhealthyHostCount(props *awscloudwatch.MetricOptions) awscloudwatch.Metric {
	if err := a.validateMetricUnhealthyHostCountParameters(props); err != nil {
		panic(err)
	}
	var returns awscloudwatch.Metric

	_jsii_.Invoke(
		a,
		"metricUnhealthyHostCount",
		[]interface{}{props},
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) RegisterConnectable(connectable awsec2.IConnectable, portRange awsec2.Port) {
	if err := a.validateRegisterConnectableParameters(connectable); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		a,
		"registerConnectable",
		[]interface{}{connectable, portRange},
	)
}

func (a *jsiiProxy_ApplicationTargetGroup) RegisterListener(listener IApplicationListener, associatingConstruct constructs.IConstruct) {
	if err := a.validateRegisterListenerParameters(listener); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		a,
		"registerListener",
		[]interface{}{listener, associatingConstruct},
	)
}

func (a *jsiiProxy_ApplicationTargetGroup) SetAttribute(key *string, value *string) {
	if err := a.validateSetAttributeParameters(key); err != nil {
		panic(err)
	}
	_jsii_.InvokeVoid(
		a,
		"setAttribute",
		[]interface{}{key, value},
	)
}

func (a *jsiiProxy_ApplicationTargetGroup) ToString() *string {
	var returns *string

	_jsii_.Invoke(
		a,
		"toString",
		nil, // no parameters
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) ValidateHealthCheck() *[]*string {
	var returns *[]*string

	_jsii_.Invoke(
		a,
		"validateHealthCheck",
		nil, // no parameters
		&returns,
	)

	return returns
}

func (a *jsiiProxy_ApplicationTargetGroup) ValidateTargetGroup() *[]*string {
	var returns *[]*string

	_jsii_.Invoke(
		a,
		"validateTargetGroup",
		nil, // no parameters
		&returns,
	)

	return returns
}

