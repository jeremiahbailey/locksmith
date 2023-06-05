package locksmith

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"

	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// Directive is used to tell the 'locksmith' what operations to perform.
type Directive struct {

	// In a future version, this field will be used to allow
	// for specifying whether a GCP service account key or
	// API Key is the target. Support may be extended for all
	// secrets/keys on GCP that developers need/want to rotate.
	RotationType string `json:"rotationType,omitempty"`

	// The service account email whose keys will be rotated
	ServiceAccountEmail string `json:"serviceAccountEmail"`

	// The application service account that needs access to the secret
	ApplicationServiceAccount string `json:"applicationServiceAccount"`

	// Option to disable the secret version. If true, all previous versions
	// of the secret will be disabled.
	DisableSecretVersions bool `json:"disableSecretVersions,omitempty"`

	// Option to disable the key. If true all previous serviceAccount
	// keys will be disabled.
	DisableServiceAccountKeys bool `json:"disableServiceAccountKeys,omitempty"`

	// The name of the secret. ex: my-prod-secret
	// If omitted, a new secret will be created, unless an
	// existing secret can be found that is tied to the same service account.
	SecretName string `json:"secretName,omitempty"`
}

// CreateServiceAccountKey creates a service account key, and if DisableServiceAccountKeys
// is set to 'true' in the directive, it will disable all other service account keys for that service
// account. It will return one of []byte or error. The []byte (the KeyFile) contains the key material
// of the service account. This should be treated as a secret and should only ever be placed in secret manager.
func CreateServiceAccountKey(ctx context.Context, serviceAccountEmail string, disableAction bool) ([]byte, error) {
	log.Println("Starting the process to create service account key...")

	iamService, err := iam.NewService(ctx)
	if err != nil {
		return nil, err
	}
	serviceAccount := fmt.Sprintf("projects/-/serviceAccounts/%v", serviceAccountEmail)

	// This will disable the service account keys if the directive states to do so.
	if disableAction {
		disableServiceAccountKeys(iamService, serviceAccount)
	}

	request := &iam.CreateServiceAccountKeyRequest{}

	key, err := iamService.Projects.ServiceAccounts.Keys.Create(serviceAccount, request).Do()
	if err != nil {
		return nil, err
	}

	log.Printf("Created service account key: %v", serviceAccount)

	keyFile, err := base64.StdEncoding.DecodeString(key.PrivateKeyData)
	if err != nil {
		return nil, err
	}

	return keyFile, err
}

// Disable any existing keys for the service account.
func disableServiceAccountKeys(iamService *iam.Service, serviceAccount string) error {
	resp, err := iamService.Projects.ServiceAccounts.Keys.List(serviceAccount).Do()
	if err != nil {
		return err
	}

	var disable iam.DisableServiceAccountKeyRequest

	for _, v := range resp.Keys {
		if !v.Disabled {
			_, err = iamService.Projects.ServiceAccounts.Keys.Disable(v.Name, &disable).Do()
			if err != nil {
				return err
			}
			log.Printf("Disabled the key: %v", v.Name)
		}

	}
	return err
}

// Create a new secret version and vaults the given value in that version.
// If DisableSecretVersions is set to 'true' in the Directive, all other
// version of the secret will be disabled.
func VaultKey(ctx context.Context, sm *secretmanager.Client, key []byte, secretName string, disableSecretAction bool) error {
	log.Println("Starting the key vaulting process...")

	if disableSecretAction {
		disableSecretVersions(ctx, sm, secretName)
	}

	req := &secretmanagerpb.AddSecretVersionRequest{
		Payload: &secretmanagerpb.SecretPayload{
			Data: key,
		},
		Parent: secretName,
	}

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

// Creates a secret in the given projectID and labels it.
func createSecret(ctx context.Context, sm *secretmanager.Client, projectID string, serviceAccountEmail string) (string, error) {

	s := fmt.Sprintf("lsm-%v-%v", projectID, rand.Intn(100000))

	labels := make(map[string]string)
	labels["islsm"] = "true"
	labels["serviceaccountemail"] = strings.ReplaceAll(strings.ReplaceAll(serviceAccountEmail, "@", "-"), ".", "-")
	createSecretRequest := &secretmanagerpb.CreateSecretRequest{
		Parent:   fmt.Sprintf("projects/%v", projectID),
		SecretId: s,
		Secret: &secretmanagerpb.Secret{
			Labels: labels,
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{}}},
		},
	}

	resp, err := sm.CreateSecret(ctx, createSecretRequest)

	if err != nil {
		return "", err
	}

	return resp.Name, nil
}

// Checks if a secret exists or not for the given service account by checking secret labels that may have the email
// address of the service account. If a secret has a matching label, we don't need to create a new secret for the new
// service account key.
func checkForSecret(ctx context.Context, sm *secretmanager.Client, projectID string, serviceAccountEmail string) (string, bool, error) {

	req := &secretmanagerpb.ListSecretsRequest{
		Parent: fmt.Sprintf("projects/%v", projectID),
		Filter: fmt.Sprintf("labels.islsm=true AND labels.serviceaccountemail=%v", strings.ReplaceAll(strings.ReplaceAll(serviceAccountEmail, "@", "-"), ".", "-")),
	}
	it := sm.ListSecrets(context.TODO(), req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return "", false, err
		}

		if resp.Name != "" {
			return resp.Name, true, nil
		}
	}
	return "", false, nil
}

// TODO: Implement a process that will allow for rotating all service account keys
// by listing all projects, all SAs in those projects, and then queueing them to be rotated
// by existing functions.

// Authoritative grant to access the secret data. Overwrites any existing policy.
func grantSecretAccessor(ctx context.Context, sm *secretmanager.Client, secretName string, applicationServiceAccount string) error {

	req := &iampb.SetIamPolicyRequest{
		Resource: secretName,
		Policy: &iampb.Policy{
			Bindings: []*iampb.Binding{
				{
					Members: []string{"serviceAccount:" + applicationServiceAccount},
					Role:    "roles/secretmanager.secretAccessor",
				},
			},
		},
	}
	pol, err := sm.SetIamPolicy(ctx, req)
	if err != nil {
		return err
	}

	log.Printf("new policy was created for secret: %v", pol)
	return nil
}

// Ensures required values are provided in the directive.
func (d Directive) validateDirective() (bool, error) {

	if d.ServiceAccountEmail == "" || d.ApplicationServiceAccount == "" {

		return false, fmt.Errorf("both ServiceAccountEmail and ApplicationServiceAccount email must be provided.ServiceAccountEmail received was %v and ApplicationServiceAccount provided was %v", d.ServiceAccountEmail, d.ApplicationServiceAccount)
	}

	return true, nil
}

// Cloud Function entrypoint.
func Handler(w http.ResponseWriter, r *http.Request) {
	var d Directive
	err := json.NewDecoder(r.Body).Decode(&d)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	sm, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	switch isValid, err := d.validateDirective(); isValid {
	case true:

		serviceAccountKey, err := CreateServiceAccountKey(ctx, d.ServiceAccountEmail, d.DisableServiceAccountKeys)
		if err != nil {
			log.Fatal(err)
		}
		projectID := os.Getenv("SecureStoreProjectID")

		secretName, exists, err := checkForSecret(ctx, sm, projectID, d.ServiceAccountEmail)
		if err != nil {
			log.Fatal(err)
		}
		switch exists {
		case true:
			err = VaultKey(ctx, sm, serviceAccountKey, secretName, d.DisableSecretVersions)
			if err != nil {
				log.Fatal(err)
			}
			err = grantSecretAccessor(ctx, sm, secretName, d.ApplicationServiceAccount)
			if err != nil {
				log.Fatal(err)
			}
		default:
			secretName, err := createSecret(ctx, sm, projectID, d.ServiceAccountEmail)
			if err != nil {
				log.Fatal(err)
			}

			formattedSecretName := fmt.Sprintf("projects/%v/secrets/%v", projectID, secretName)
			VaultKey(ctx, sm, serviceAccountKey, formattedSecretName, false)
			err = grantSecretAccessor(ctx, sm, secretName, d.ApplicationServiceAccount)
			if err != nil {
				log.Fatal(err)
			}

		}

	default:
		log.Fatal(err)
	}

}
