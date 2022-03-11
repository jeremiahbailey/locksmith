package locksmith

/*

Locksmith allows you to automatically manage the creation, vaulting, rotation, and disabling
of GCP Service Account Keys. Locksmith also allows you to optionally disable secrets versions
in GCP Secret Manager.

Locksmith is intended to be used withing a background Cloud Function on GCP. The entire solution would
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
	"fmt"
	"log"

	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"

	secretmanager "cloud.google.com/go/secretmanager/apiv1beta1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1beta1"
)

// Directive is used to tell the 'locksmith' what operations to perform.
type Directive struct {

	// In a future version, this field will be used to allow
	// for specifying whether a GCP service account key or
	// API Key is the target. Support may be extended for all
	// secrets/keys on GCP that developers need/want to rotate.
	RotationType string `json:"rotation_type,omitempty"`

	// The email of the service account.
	ServiceAccountEmail string `json:"service_account_email"`

	// Option to disable the secret version. If true, all previous versions
	// of the secret will be disabled.
	DisableSecretVersions bool `json:"disable_secret_versions,omitempty"`

	// Option to disable the key. If true all previous serviceAccount
	// keys will be disabled.
	DisableServiceAccoutKeys bool `json:"disable_service_account_keys,omitempty"`

	// The ID of the GCP Project. ex: my-new-prj-123
	ProjectID string `json:"project_id"`

	// The name of the secret. ex: my-prod-secret
	SecretName string `json:"secret_name"`
}

// KeyFile is the Service Account Key.
// It is the secret that will be vaulted
// in Secret Manager.
var KeyFile []byte

// CreateServiceAccountKey creates a service account key, and if DisableServiceAccountKeys
// is set to 'true' in the directive, it will disable all other service account keys for that service
// account. It will return one of []byte or error. The []byte (the KeyFile) contains the key material
// of the service account. This should be treated as a secret and should only ever be placed in secret manager.
func CreateServiceAccountKey(ctx context.Context, msg Directive) ([]byte, error) {
	log.Println("Starting the process to create service account key...")

	iamService, err := iam.NewService(ctx)
	if err != nil {
		return nil, err
	}

	serviceAccount := fmt.Sprintf("projects/%v/serviceAccounts/%v", msg.ProjectID, msg.ServiceAccountEmail)

	// This will disable the service account keys if the directive states to do so.
	if msg.DisableServiceAccoutKeys {
		disableServiceAccountKeys(iamService, serviceAccount)
	}

	request := &iam.CreateServiceAccountKeyRequest{}

	key, err := iamService.Projects.ServiceAccounts.Keys.Create(serviceAccount, request).Do()
	if err != nil {
		return nil, err
	}

	log.Printf("Created service account key: %v", serviceAccount)

	KeyFile, err = base64.StdEncoding.DecodeString(key.PrivateKeyData)
	if err != nil {
		return nil, err
	}

	return KeyFile, err
}

// Disable any existing keys for the service account.
func disableServiceAccountKeys(iamService *iam.Service, serviceAccount string) error {
	resp, err := iamService.Projects.ServiceAccounts.Keys.List(serviceAccount).Do()
	if err != nil {
		return err
	}

	var disable iam.DisableServiceAccountKeyRequest

	for _, v := range resp.Keys {
		_, err = iamService.Projects.ServiceAccounts.Keys.Disable(v.Name, &disable).Do()
		if err != nil {
			return err
		}
		log.Printf("Disabled the key: %v", v.Name)
	}
	return err
}

// Create a new secret version and vaults the given value in that version.
// If DisableSecretVersions is set to 'true' in the Directive, all other
// version of the secret will be disabled.
func VaultKey(ctx context.Context, key []byte, d Directive) error {
	log.Println("Starting the key vaulting process...")

	sm, err := secretmanager.NewClient(ctx)
	if err != nil {
		return err
	}

	secret := fmt.Sprintf("projects/%v/secrets/%v", d.ProjectID, d.SecretName)

	if d.DisableSecretVersions {
		disableSecretVersions(ctx, sm, secret)
	}
	req := &secretmanagerpb.AddSecretVersionRequest{}
	payload := &secretmanagerpb.SecretPayload{}
	payload.Data = key
	req.Parent = secret
	req.Payload = payload

	version, err := sm.AddSecretVersion(ctx, req)
	if err != nil {
		return err
	}

	log.Printf("Created secret version: %v", version.Name)
	return err
}

// Disables all secret versions for a given secret.
func disableSecretVersions(ctx context.Context, sm *secretmanager.Client, secret string) error {
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
			return err
		}

		if resp.State == 1 {
			disableSecretVersion := &secretmanagerpb.DisableSecretVersionRequest{}
			disableSecretVersion.Name = resp.Name
			version, err := sm.DisableSecretVersion(ctx, disableSecretVersion)

			if err != nil {
				return err
			}
			log.Printf("Disabled version: %v", version.Name)
		}

	}
	return nil
}
