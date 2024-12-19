//go:build no_runtime_type_checking

package awsroute53

// Building without runtime type checking enabled, so all the below just return nil

func (a *jsiiProxy_AaaaRecord) validateApplyRemovalPolicyParameters(policy awscdk.RemovalPolicy) error {
	return nil
}

func (a *jsiiProxy_AaaaRecord) validateGetResourceArnAttributeParameters(arnAttr *string, arnComponents *awscdk.ArnComponents) error {
	return nil
}

func (a *jsiiProxy_AaaaRecord) validateGetResourceNameAttributeParameters(nameAttr *string) error {
	return nil
}

func validateAaaaRecord_IsConstructParameters(x interface{}) error {
	return nil
}

func validateAaaaRecord_IsOwnedResourceParameters(construct constructs.IConstruct) error {
	return nil
}

func validateAaaaRecord_IsResourceParameters(construct constructs.IConstruct) error {
	return nil
}

func validateNewAaaaRecordParameters(scope constructs.Construct, id *string, props *AaaaRecordProps) error {
	return nil
}

