package main

import (
	"fmt"
	"sync/atomic"
	"time"
)

var alertCounter uint64

// newAlertID mirrors Wazuh's "<epoch>.<seq>" alert id shape so ids are unique
// and roughly time-ordered.
func newAlertID() string {
	n := atomic.AddUint64(&alertCounter, 1)
	return fmt.Sprintf("%d.%d", time.Now().Unix(), n)
}
