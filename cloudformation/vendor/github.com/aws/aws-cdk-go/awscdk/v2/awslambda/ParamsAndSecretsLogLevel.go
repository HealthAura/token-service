package awslambda


// Logging levels for the Parametes and Secrets Extension.
//
// Example:
//   import sm "github.com/aws/aws-cdk-go/awscdk"
//   import ssm "github.com/aws/aws-cdk-go/awscdk"
//
//
//   secret := sm.NewSecret(this, jsii.String("Secret"))
//   parameter := ssm.NewStringParameter(this, jsii.String("Parameter"), &StringParameterProps{
//   	ParameterName: jsii.String("mySsmParameterName"),
//   	StringValue: jsii.String("mySsmParameterValue"),
//   })
//
//   paramsAndSecrets := lambda.ParamsAndSecretsLayerVersion_FromVersion(lambda.ParamsAndSecretsVersions_V1_0_103, &ParamsAndSecretsOptions{
//   	CacheSize: jsii.Number(500),
//   	LogLevel: lambda.ParamsAndSecretsLogLevel_DEBUG,
//   })
//
//   lambdaFunction := lambda.NewFunction(this, jsii.String("MyFunction"), &FunctionProps{
//   	Runtime: lambda.Runtime_NODEJS_18_X(),
//   	Handler: jsii.String("index.handler"),
//   	Architecture: lambda.Architecture_ARM_64(),
//   	Code: lambda.Code_FromAsset(path.join(__dirname, jsii.String("lambda-handler"))),
//   	ParamsAndSecrets: ParamsAndSecrets,
//   })
//
//   secret.grantRead(lambdaFunction)
//   parameter.grantRead(lambdaFunction)
//
type ParamsAndSecretsLogLevel string

const (
	// Debug.
	ParamsAndSecretsLogLevel_DEBUG ParamsAndSecretsLogLevel = "DEBUG"
	// Info.
	ParamsAndSecretsLogLevel_INFO ParamsAndSecretsLogLevel = "INFO"
	// Warn.
	ParamsAndSecretsLogLevel_WARN ParamsAndSecretsLogLevel = "WARN"
	// Error.
	ParamsAndSecretsLogLevel_ERROR ParamsAndSecretsLogLevel = "ERROR"
	// No logging.
	ParamsAndSecretsLogLevel_NONE ParamsAndSecretsLogLevel = "NONE"
)

