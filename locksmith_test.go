package locksmith

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
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
