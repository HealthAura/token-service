package awssagemaker


// Specifies the location of ML model data to deploy.
//
// If specified, you must specify one and only one of the available data sources.
//
// Example:
//   // The code below shows an example of how to instantiate this type.
//   // The values are placeholders you should change.
//   import "github.com/aws/aws-cdk-go/awscdk"
//
//   modelDataSourceProperty := &ModelDataSourceProperty{
//   	S3DataSource: &S3ModelDataSourceProperty{
//   		CompressionType: jsii.String("compressionType"),
//   		S3DataType: jsii.String("s3DataType"),
//   		S3Uri: jsii.String("s3Uri"),
//
//   		// the properties below are optional
//   		ModelAccessConfig: &ModelAccessConfigProperty{
//   			AcceptEula: jsii.Boolean(false),
//   		},
//   	},
//   }
//
// See: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sagemaker-modelpackage-modeldatasource.html
//
type CfnModelPackage_ModelDataSourceProperty struct {
	// Specifies the S3 location of ML model data to deploy.
	// See: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sagemaker-modelpackage-modeldatasource.html#cfn-sagemaker-modelpackage-modeldatasource-s3datasource
	//
	S3DataSource interface{} `field:"optional" json:"s3DataSource" yaml:"s3DataSource"`
}

