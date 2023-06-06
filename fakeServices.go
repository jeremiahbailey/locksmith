package locksmith

import (
	"context"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type fakeSecretManagerService struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
}

func (sm *fakeSecretManagerService) CreateSecret(context.Context, *secretmanagerpb.CreateSecretRequest) (*secretmanagerpb.Secret, error) {

	labels := make(map[string]string)

	labels["islsm"] = "true"
	labels["serviceaccountemail"] = "myFakeSA-myfakeproject-iam-gserviceaccount-com"

	return &secretmanagerpb.Secret{
		Name:   "projects/myfakeproject/secrets/lsm-myfakeproject-75788",
		Labels: labels,
	}, nil
}
