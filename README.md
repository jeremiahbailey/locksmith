# locksmith
 Locksmith allows you to create GCP Service Account keys, vault them in secret manager, rotate the keys and secrets, and disable both keys and versions.


```go
package cloudfunctionexample

import (
	"context"
	"encoding/json"
	"log"

	"github.com/jeremiahbailey/locksmith"
)

type PubSubMessage struct {
	Data []byte `json:"data"`
}

// Unmarshals the PubSub message into the Message.
func unmarshalMessage(m PubSubMessage) locksmith.Directive {
	log.Println("Starting to unmarshal the message...")
	var d locksmith.Directive
	json.Unmarshal(m.Data, &d)

	return d

}

func ProcessEvent(ctx context.Context, m PubSubMessage) error {
	d := unmarshalMessage(m)

	if d.RotationType == "serviceAccountKey" {
		key, err := locksmith.CreateServiceAccountKey(ctx, d)
		if err != nil {
			log.Fatal(err)
		}
		locksmith.VaultKey(ctx, key, d)

	}

	if d.RotationType != "serviceAccountKey" {
		log.Fatal("Only serviceAccountKeyRotations are currently supported.")
	}

	return nil
}

```