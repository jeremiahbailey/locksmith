package locksmith

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"

	secretmanager "cloud.google.com/go/secretmanager/apiv1beta1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1beta1"
)

// PubSubMessage is the message from the topic.
type PubSubMessage struct {
	Data []byte `json:"data"`
}

// Message is the message published into the topic from the scheduler.
type Message struct {
	RotateKey string `json:"rotatekey,omitempty"`
}

// createServiceAccountKey creates a service account key
// and calls a helper function to ensure all other keys
// for that service account are disabled.
func createServiceAccountKey(ctx context.Context) []byte {
	log.Println("Starting the process to create service account key...")

	projectID := os.Getenv("PROJECT_ID")
	serviceAccountEmail := os.Getenv("SERVICE_ACCOUNT_EMAIL")

	iamService, err := iam.NewService(ctx)
	if err != nil {
		log.Fatalf("error creating iam service: %v", err)
	}
	serviceAccount := fmt.Sprintf("projects/%v/serviceAccounts/%v", projectID, serviceAccountEmail)

	disableServiceAccountKey(iamService, serviceAccount)
	var request iam.CreateServiceAccountKeyRequest

	key, err := iamService.Projects.ServiceAccounts.Keys.Create(serviceAccount, &request).Do()
	log.Printf("Created service account key: %v", key.Name)
	if err != nil {
		log.Fatal(err)
	}

	var b pem.Block

	b.Type = "PRIVATE KEY"
	b.Bytes = []byte(key.PrivateKeyData)

	pemKey := pem.EncodeToMemory(&b)
	return pemKey

}

// Disable any existing keys for the service account.
func disableServiceAccountKey(iamService *iam.Service, serviceAccount string) {
	resp, err := iamService.Projects.ServiceAccounts.Keys.List(serviceAccount).Do()
	if err != nil {
		panic(err)
	}

	var disable iam.DisableServiceAccountKeyRequest

	for _, v := range resp.Keys {
		iamService.Projects.ServiceAccounts.Keys.Disable(v.Name, &disable).Do()
		log.Printf("Disabled the key: %v", v.Name)
	}
}

// Create a new secret version and vaults a PEM formatted key
// in that version.
func vaultKey(ctx context.Context, key []byte) {
	log.Println("Starting the key vaulting process...")
	secretName := os.Getenv("SECRET_NAME")
	projectID := os.Getenv("PROJECT_ID")
	sm, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	secret := fmt.Sprintf("projects/%v/secrets/%v", projectID, secretName)

	disableSecretVersions(ctx, sm, secret)

	var req secretmanagerpb.AddSecretVersionRequest
	var payload secretmanagerpb.SecretPayload
	payload.Data = key
	req.Parent = secret
	req.Payload = &payload

	version, err := sm.AddSecretVersion(ctx, &req)
	if err != nil {
		panic(err)
	}

	log.Printf("Created secret version: %v", version.Name)

}

// Disables all secret versions for a given secret.
func disableSecretVersions(ctx context.Context, sm *secretmanager.Client, secret string) {
	log.Println("Checking if there are previous versions to disable...")
	var listRequest secretmanagerpb.ListSecretVersionsRequest
	listRequest.Parent = secret

	it := sm.ListSecretVersions(ctx, &listRequest)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			panic(err)
		}

		if resp.State == 1 {
			var disableSecretVersion secretmanagerpb.DisableSecretVersionRequest
			disableSecretVersion.Name = resp.Name
			sm.DisableSecretVersion(ctx, &disableSecretVersion)
			log.Printf("Disabled version: %v", resp.Name)
		}

	}
}

// Unmarshals the PubSub message into the Message.
func unmarshalMessage(m PubSubMessage) Message {
	log.Println("Starting to unmarshal the message...")
	var msg Message
	json.Unmarshal(m.Data, &msg)

	return msg

}

func ProcessEvent(ctx context.Context, m PubSubMessage) error {
	msg := unmarshalMessage(m)

	if msg.RotateKey == "true" {
		saKey := createServiceAccountKey(ctx)
		vaultKey(ctx, saKey)
	}

	return nil
}
