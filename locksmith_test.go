package locksmith

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
)

func TestCreateServiceAccountKey(t *testing.T) {
	expectedKeyName := "projects/somefakeprojectid/serviceAccounts/103317855469044444/keys/65d58e12a436f5748e2e13a73938c0d50c9eff94"
	ctx := context.Background()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &iam.ServiceAccountKey{
			Name:     expectedKeyName,
			Disabled: false,
		}
		b, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "unable to marshal request: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Write(b)
	}))
	defer ts.Close()

	svc, err := iam.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(ts.URL))
	if err != nil {
		t.Fatalf("unable to create client: %v", err)
	}

	got, err := CreateServiceAccountKey(ctx, svc, "myFakeSA@somefakeprojectid.iam.gserviceaccount.com", false)
	if err != nil {
		t.Fatal(err)
	}

	if got.Name != expectedKeyName {
		t.Fatalf("expected %v, got %v", expectedKeyName, got.Name)
	}

	if got.Disabled {
		t.Fatalf("expected %v, got %v", false, got.Disabled)
	}
}

func TestCreateSecret(t *testing.T) {

	expectedLabels := make(map[string]string)
	expectedLabels["islsm"] = "true"
	expectedLabels["serviceaccountemail"] = "myFakeSA-myfakeproject-iam-gserviceaccount-com"

	expectedSecretName := "projects/myfakeproject/secrets/lsm-myfakeproject-75788"

	ctx := context.Background()
	fakeSecretManagerService := &fakeSecretManagerService{}
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	gsrv := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(gsrv, fakeSecretManagerService)
	fakeServerAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err)
		}
	}()

	// Create a client.
	client, err := secretmanager.NewClient(ctx,
		option.WithEndpoint(fakeServerAddr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithInsecure()),
	)
	if err != nil {
		t.Fatal(err)
	}

	got, err := createSecret(ctx, client, "myfakeproject", "myFakeSA@myfakeproject.iam.gserviceaccount.com")
	if err != nil {
		t.Fatal(err)
	}

	if got.Name != expectedSecretName {
		t.Fatalf("expected %v, got %v", expectedSecretName, got.Name)
	}

	for k, v := range got.Labels {
		if k == "islsm" && v != "true" {
			t.Fatalf("expected %v, got %v", expectedLabels["islsm"], v)
		}

		if k == "serviceaccountemail" && v != "myFakeSA-myfakeproject-iam-gserviceaccount-com" {
			t.Fatalf("expected %v, got %v", expectedLabels["serviceaccountemail"], v)
		}

		if k != "islsm" && k != "serviceaccountemail" {
			t.Fatalf("expected labels %v, got %v", expectedLabels, got.Labels)
		}
	}
}
