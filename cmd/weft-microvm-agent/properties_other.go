//go:build !linux

package main

import (
	"errors"

	"github.com/openweft/weft-microvm-agent/pkg/properties"
)

func propertiesApplyer(_ string) properties.ApplyFunc {
	return func(properties.PropertySet) error {
		return errors.New("properties apply is Linux-only ; weft-microvm-agent runs inside a Linux microVM")
	}
}
