//go:build no_runtime_type_checking

package awsapigateway

// Building without runtime type checking enabled, so all the below just return nil

func (i *jsiiProxy_IAccessLogDestination) validateBindParameters(stage IStage) error {
	return nil
}

