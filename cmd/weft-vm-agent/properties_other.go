//go:build !linux

package main

import (
	"errors"

	"github.com/openweft/weft-vm-agent/pkg/properties"
)

func propertiesApplyer(_ string) properties.ApplyFunc {
	return func(properties.PropertySet) error {
		return errors.New("properties apply is Linux-only ; weft-vm-agent runs inside a Linux microVM")
	}
}
