//go:build !no_runtime_type_checking

package awsdynamodb

import (
	"fmt"

	_jsii_ "github.com/aws/jsii-runtime-go/runtime"
)

func validateCapacity_AutoscaledParameters(options *AutoscaledCapacityOptions) error {
	if options == nil {
		return fmt.Errorf("parameter options is required, but nil was provided")
	}
	if err := _jsii_.ValidateStruct(options, func() string { return "parameter options" }); err != nil {
		return err
	}

	return nil
}

func validateCapacity_FixedParameters(iops *float64) error {
	if iops == nil {
		return fmt.Errorf("parameter iops is required, but nil was provided")
	}

	return nil
}

