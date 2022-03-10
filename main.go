package locksmith

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

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
	RotationType          string `json:"rotation_type"`                     // one of serviceAccountKey or APIKey is accepted
	APIKeyName            string `json:"api_key_name,omitempty"`            // the name of the API key
	ServiceAccountLDAP    string `json:"service_account_ldap,omitempty"`    // the LDAP of the service account key
	DisableSecretVersions bool   `json:"disable_secret_versions,omitempty"` // option to disable the secret version
	DisableKeys           bool   `json:"disable_keys,omitempty"`            // option to disable the key. If true all previous API Key or serviceAccount keys will be disables
	ProjectID             string `json:"project_id"`
	SecretName            string `json:"secret_name"`
}

// createServiceAccountKey creates a service account key.
func createServiceAccountKey(ctx context.Context, msg Message) []byte {
	log.Println("Starting the process to create service account key...")

	iamService, err := iam.NewService(ctx)
	if err != nil {
		log.Fatalf("error creating iam service: %v", err)
	}

	serviceAccount := fmt.Sprintf("projects/%v/serviceAccounts/%v", msg.ProjectID, msg.ServiceAccountLDAP)

	if msg.DisableKeys {
		disableServiceAccountKeys(iamService, serviceAccount)
	}

	var request iam.CreateServiceAccountKeyRequest

	key, err := iamService.Projects.ServiceAccounts.Keys.Create(serviceAccount, &request).Do()
	log.Printf("Created service account key: %v", key.Name)
	if err != nil {
		log.Fatal(err)
	}

	jsonKeyFile, err := base64.StdEncoding.DecodeString(key.PrivateKeyData)
	if err != nil {
		log.Fatal(err)
	}

	return jsonKeyFile
}

// Disable any existing keys for the service account.
func disableServiceAccountKeys(iamService *iam.Service, serviceAccount string) {
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

// Create a new secret version and vaults the given value in that version.
func vaultKey(ctx context.Context, key []byte, msg Message) {
	log.Println("Starting the key vaulting process...")

	sm, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	secret := fmt.Sprintf("projects/%v/secrets/%v", msg.ProjectID, msg.SecretName)

	if msg.DisableSecretVersions {
		disableSecretVersions(ctx, sm, secret)
	}
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

	if msg.RotationType == "serviceAccountKey" {
		key := createServiceAccountKey(ctx, msg)
		vaultKey(ctx, key, msg)

	}

	return nil
}
