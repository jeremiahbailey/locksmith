package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"

	secretmanager "cloud.google.com/go/secretmanager/apiv1beta1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1beta1"
)

/*

IAM API has to be enabled in the project.


deployment pattern:
- scheduler to run once a year -- msg == rotateSecret = True
- scheduler to run every 375 days -- 10days after rotation. -- deletekey = True
- first time, manually publish message to topic
- delete service account key a few hours/days after rotating the secret
- disable previous version of the secret. when rotating key. -- if not "latest" {delete version}
- delete previous secret once original key is deleted.
*/

type PubSubMessage struct {
	Data []byte `json:"data"`
}

type Message struct {
	DeleteKey string `json:"deletekey,omitempty"`
	RotateKey string `json:"rotatekey,omitempty"`
}

func createServiceAccountKey(ctx context.Context) []byte {
	projectID := os.Getenv("PROJECT_ID")
	serviceAccountEmail := os.Getenv("SERVICE_ACCOUNT_EMAIL")

	iamService, err := iam.NewService(ctx)
	if err != nil {
		log.Fatalf("error creating iam service: %v", err)
	}
	serviceAccount := fmt.Sprintf("projects/%v/serviceAccounts/%v", projectID, serviceAccountEmail)

	resp, err := iamService.Projects.ServiceAccounts.Keys.List(serviceAccount).Do()
	if err != nil {
		panic(err)
	}

	var disable iam.DisableServiceAccountKeyRequest

	for _, v := range resp.Keys {

		iamService.Projects.ServiceAccounts.Keys.Disable(v.Name, &disable).Do()
	}
	var request iam.CreateServiceAccountKeyRequest

	key, err := iamService.Projects.ServiceAccounts.Keys.Create(serviceAccount, &request).Do()

	if err != nil {
		log.Fatal(err)
	}

	var b pem.Block

	b.Type = "PRIVATE KEY"
	b.Bytes = []byte(key.PrivateKeyData)

	key1 := pem.EncodeToMemory(&b)
	return key1

}

func vaultKey(ctx context.Context, key []byte) {

	secretName := os.Getenv("SECRET_NAME")
	projectID := os.Getenv("PROJECT_ID")
	sm, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	secret := fmt.Sprintf("projects/%v/secrets/%v", projectID, secretName)
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
		}

	}
	var req secretmanagerpb.AddSecretVersionRequest
	var payload secretmanagerpb.SecretPayload
	payload.Data = key
	req.Parent = secret
	req.Payload = &payload

	sm.AddSecretVersion(ctx, &req)

}

func main() {
	ctx := context.Background()
	key := createServiceAccountKey(ctx)
	vaultKey(ctx, key)
}

// func unmarshalMessage(m PubSubMessage) Message {
// 	var msg Message
// 	json.Unmarshal(m.Data, &msg)

// 	return msg

// }

// func ProcessEvent(ctx context.Context, m PubSubMessage) error {
// 	msg := unmarshalMessage(m)

// 	if msg.RotateKey == "true" {
// 		saKey := createServiceAccountKey(ctx)
// 		vaultKey(ctx, saKey)
// 	}

// 	return nil
// }
