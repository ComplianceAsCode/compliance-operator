package framework

import "time"

const (
	retryInterval                 = time.Second * 5
	timeout                       = time.Minute * 30
	maxRetries                    = 5
	cleanupTimeout                = time.Minute * 5
	cleanupRetryInterval          = time.Second * 1
	testPoolName                  = "e2e"
	workerPoolName                = "worker"
	testInvalidPoolName           = "e2e-invalid"
	machineOperationRetryInterval = time.Second * 10
	machineOperationTimeout       = time.Minute * 25
	RhcosContentFile              = "ssg-rhcos4-ds.xml"
)