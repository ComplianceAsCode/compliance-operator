package utils

import (
	"context"

	backoff "github.com/cenkalti/backoff/v4"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	log        = logf.Log.WithName("clientutils")
	maxRetries = uint64(15)
)

// GetObjectIfFound retrieves an object with retry logic and returns whether it exists.
// It uses exponential backoff to retry on transient errors.
// Returns true if the object was found, false if it doesn't exist.
// The obj parameter will be updated with the retrieved object data if found.
func GetObjectIfFound(client runtimeclient.Client, key types.NamespacedName, obj runtimeclient.Object) bool {
	var found bool
	err := backoff.Retry(func() error {
		err := client.Get(context.TODO(), key, obj)
		if errors.IsNotFound(err) {
			// Not found is not an error we want to retry
			return nil
		} else if err != nil {
			log.Info("Retrying with a backoff because of an error while getting object", "error", err)
			return err
		}
		found = true
		return nil
	}, backoff.WithMaxRetries(backoff.NewExponentialBackOff(), maxRetries))

	if err != nil {
		log.Error(err, "Couldn't get object", "Name", key.Name, "Namespace", key.Namespace)
	}
	return found
}
