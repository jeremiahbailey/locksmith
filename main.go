package locksmith

/*

Locksmith allows you to automatically manage the creation, vaulting, rotation, and disabling
of GCP Service Account Keys. Locksmith also allows you to optionally disable secrets versions
in GCP Secret Manager.

Locksmith is designed to be deployed as a background Cloud Function on GCP. The entire solution would
consist of a Cloud Scheduler job that would be responsible for ensuring each Service Account in a given
GCP project has its keys rotated on a regular schedule. The Cloud Function's service account will need
to be granted the requisite roles to create and disable Service Account keys and Secret versions.


Example Message:

{
    "rotation_type": "serviceAccountKey",
    "service_account_email": "myserviceacccount@myprojectid.iam.gserviceaccount.com",
    "disable_secret_versions": true,
    "disable_service_account_keys": false,
    "project_id": "my-project-id",
    "secret_name": "my-secret"
}

In the example above, the Cloud Function will attempt to create a new service account key for
the "myserviceacccount@myprojectid.iam.gserviceaccount.com" account; create a new version for
the secret "my-secret" and disable all other secret versions. It will *not* disable the existing
keys for the service account.

*/

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

// Directive is the directive published into the topic from the scheduler.
type Directive struct {

	// only serviceAccount is currently accepted.
	RotationType string `json:"rotation_type"`

	// the email of the service account.
	ServiceAccountEmail string `json:"service_account_email,omitempty"`

	// option to disable the secret version. If true, all previous versions
	// of the secret will be disabled.
	DisableSecretVersions bool `json:"disable_secret_versions,omitempty"`

	// option to disable the key. If true all previous serviceAccount
	// keys will be disabled.
	DisableServiceAccoutKeys bool `json:"disable_service_account_keys,omitempty"`

	// the ID of the GCP Project. ex: my-new-prj-123
	ProjectID string `json:"project_id"`

	// the name of the secret. ex: my-prod-secret
	SecretName string `json:"secret_name"`
}

// createServiceAccountKey creates a service account key.
func createServiceAccountKey(ctx context.Context, msg Directive) []byte {
	log.Println("Starting the process to create service account key...")

	iamService, err := iam.NewService(ctx)
	if err != nil {
		log.Fatalf("error creating iam service: %v", err)
	}

	serviceAccount := fmt.Sprintf("projects/%v/serviceAccounts/%v", msg.ProjectID, msg.ServiceAccountEmail)

	if msg.DisableServiceAccoutKeys {
		disableServiceAccountKeys(iamService, serviceAccount)
	}

	var request iam.CreateServiceAccountKeyRequest

	key, err := iamService.Projects.ServiceAccounts.Keys.Create(serviceAccount, &request).Do()
	log.Printf("Created service account key: %v", key.Name)
	if err != nil {
		log.Fatal(err)
	}

	// This contains a secret value. NEVER, NOT EVER, should this be logged.
	// ANYWHERE. UNDER ANY CIRCUMSTANCES. Yes, this applies to YOU!
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
func vaultKey(ctx context.Context, key []byte, d Directive) {
	log.Println("Starting the key vaulting process...")

	sm, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	secret := fmt.Sprintf("projects/%v/secrets/%v", d.ProjectID, d.SecretName)

	if d.DisableSecretVersions {
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
func unmarshalMessage(m PubSubMessage) Directive {
	log.Println("Starting to unmarshal the message...")
	var d Directive
	json.Unmarshal(m.Data, &d)

	return d

}

func ProcessEvent(ctx context.Context, m PubSubMessage) error {
	d := unmarshalMessage(m)

	if d.RotationType == "serviceAccountKey" {
		key := createServiceAccountKey(ctx, d)
		vaultKey(ctx, key, d)

	}

	if d.RotationType != "serviceAccountKey" {
		log.Fatal("Only serviceAccountKeyRotations are currently supported.")
	}

	return nil
}
