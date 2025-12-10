package framework

import "time"

const (
	RetryInterval                 = time.Second * 5
	ShortRetryInterval            = time.Second * 2
	Timeout                       = time.Minute * 30
	TestPoolName                  = "e2e"
	maxRetries                    = 5
	cleanupTimeout                = time.Minute * 5
	cleanupRetryInterval          = time.Second * 1
	workerPoolName                = "worker"
	testInvalidPoolName           = "e2e-invalid"
	machineOperationRetryInterval = time.Second * 10
	machineOperationTimeout       = time.Minute * 25
	RhcosContentFile              = "ssg-rhcos4-ds.xml"
	OcpContentFile                = "ssg-ocp4-ds.xml"
	UnexistentResourceContentFile = "ocp4-unexistent-resource.xml"
	PromethusTestSA               = "prometheus-query-sa"
)
