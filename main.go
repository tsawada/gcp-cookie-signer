package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type server struct {
	projectId  string
	secretName string
}

type KeyInfo struct {
	key        []byte
	name       string
	expiration time.Time
}

func main() {
	projectId := os.Getenv("GCP_PROJECT")
	port := os.Getenv("PORT")
	secretName := os.Getenv("SECRET_NAME")

	svr := &server{
		projectId:  projectId,
		secretName: secretName,
	}

	if err := http.ListenAndServe(":"+port, svr); err != nil {
		log.Fatal(err)
	}
}

func getKey(ctx context.Context, projectId, name string) (KeyInfo, error) {
	sm, err := secretmanager.NewClient(ctx)
	if err != nil {
		return KeyInfo{}, err
	}
	resourceName := fmt.Sprintf("projects/%s/secrets/%s", projectId, name)
	secret, err := sm.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
		Name: resourceName,
	})
	if err != nil {
		return KeyInfo{}, err
	}
	log.Printf("Get secret: %v", secret.GetVersionAliases())
	versionResponse, err := sm.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("%s/versions/latest", resourceName),
	})
	if err != nil {
		return KeyInfo{}, err
	}
	b := versionResponse.Payload.GetData()
	key := make([]byte, base64.URLEncoding.DecodedLen(len(b)))
	n, err := base64.URLEncoding.Decode(key, b)
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{
			key:        key[:n],
			name:       name + "-1",
			expiration: time.Now().Add(6 * time.Hour)},
		nil
}

func signCookie(urlPrefix string, keyInfo KeyInfo) string {
	encodedURLPrefix := base64.URLEncoding.EncodeToString([]byte(urlPrefix))
	input := fmt.Sprintf("URLPrefix=%s:Expires=%d:KeyName=%s",
		encodedURLPrefix, keyInfo.expiration.Unix(), keyInfo.name)

	mac := hmac.New(sha1.New, keyInfo.key)
	mac.Write([]byte(input))
	sig := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s:Signature=%s", input, sig)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme != "https" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	domain := r.URL.Host
	keyInfo, err := getKey(ctx, s.projectId, s.secretName)
	if err != nil {
		log.Print(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	signedValue := signCookie("https://"+domain, keyInfo)
	http.SetCookie(w, &http.Cookie{
		Name:     "Cloud-CDN-Cookie",
		Value:    signedValue,
		Path:     "",
		Domain:   r.URL.Host,
		MaxAge:   int(time.Until(keyInfo.expiration).Seconds()),
		Secure:   true,
		HttpOnly: true,
	})
	http.Redirect(w, r, r.URL.String(), http.StatusFound)
}
