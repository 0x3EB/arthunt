package artifactory

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestUseBearerClearsCredentials is a white-box check that switching to a minted
// token wipes the Basic/API-key credentials, so the password/api-key is never
// sent again after minting.
func TestUseBearerClearsCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}))
	defer srv.Close()

	c, err := New(context.Background(), Options{
		BaseURL: srv.URL, User: "u", Password: "p", APIKey: "ak",
		ReqTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.UseBearer("MINTED")
	if c.opt.Token != "MINTED" {
		t.Errorf("Token=%q, want MINTED", c.opt.Token)
	}
	if c.opt.User != "" || c.opt.Password != "" || c.opt.APIKey != "" {
		t.Errorf("credentials not wiped: user=%q pass=%q apikey=%q", c.opt.User, c.opt.Password, c.opt.APIKey)
	}
}
