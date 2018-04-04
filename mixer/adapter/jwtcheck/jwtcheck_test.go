package jwtcheck

import (
	"context"
	"fmt"
	"os"
	"testing"

	"istio.io/istio/mixer/pkg/adapter/test"
	"istio.io/istio/mixer/template/authorization"
)

func TestJWTCheckAdapter(t *testing.T) {

	info := GetInfo()

	if !contains(info.SupportedTemplates, authorization.TemplateName) {
		t.Error("Didn't find all expected supported templates")
	}

	b := info.NewBuilder().(*builder)
	b.SetAdapterConfig(info.DefaultConfig)

	if err := b.Validate(); err != nil {
		t.Errorf("Got error %v, expecting success", err)
	}

	file, _ := os.Create(b.adapterConfig.FilePath)
	key := b.adapterConfig.Secret
	keybytes, _ := loadData(key)

	handler := &handler{env: test.NewEnv(t), closing: make(chan bool), done: make(chan bool), f: file, cacheDuration: 1000, key: keybytes}
	m := map[string]interface{}{"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTUyMjg2NjE2MywiZXhwIjoxNTIyODY5NzYzLCJpYXQiOjE1MjI4NjYxNjMsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.pFmvhEDI0rWi3AID0QC-houf-1CX8XRKrqjlc1X_2zg"}
	subject := authorization.Subject{User: "John", Groups: "first,second", Properties: m}
	instance := authorization.Instance{Subject: &subject}
	result, autherror := handler.HandleAuthorization(context.Background(), &instance)
	fmt.Printf("%v\n", result)
	if autherror != nil {
		t.Errorf("Got error %v, expecting success", autherror)
	}

}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
