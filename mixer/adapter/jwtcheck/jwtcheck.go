//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -f mixer/adapter/jwtcheck/config/config.proto
package jwtcheck

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"istio.io/istio/mixer/adapter/jwtcheck/config"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/mixer/template/authorization"
)

type (
	builder struct {
		adapterConfig *config.Params
	}
	handler struct {
		env           adapter.Env
		closing       chan bool
		done          chan bool
		f             *os.File
		cacheDuration time.Duration
		key           []byte
	}
)

func (b *builder) Build(ctx context.Context, env adapter.Env) (adapter.Handler, error) {
	file, err := os.Create(b.adapterConfig.FilePath)
	key := b.adapterConfig.AuthPrivateKey
	keybytes, _ := loadData(key)
	h := &handler{
		env:     env,
		closing: make(chan bool),
		done:    make(chan bool),
		f:       file,
		key:     keybytes,
	}
	h.f.WriteString("meh")

	return h, err
}

// adapter.HandlerBuilder#SetAuthorizationTypes
func (b *builder) SetAuthorizationTypes(types map[string]*authorization.Type) {
}

////////////////// Request-time Methods //////////////////////////
// authorization.Handler#HandleAuthorization
func (h *handler) HandleAuthorization(ctx context.Context, inst *authorization.Instance) (adapter.CheckResult, error) {
	h.f.WriteString("meh again")
	tokenstringraw := inst.Action.Properties["Authorization"].(string)
	tokenstring := parseParam(tokenstringraw)
	tokenisvalid, claims, _ := parseToken(tokenstring, h.key)
	s := status.WithPermissionDenied("Token is invalid")
	if tokenisvalid {
		s = status.OK
	}

	h.f.WriteString(fmt.Sprintf(`Handle Authorization invoke for : 
		Instance Name : '%s'
		Action Path : '%s'
		Claims : '%v'`,
		inst.Name, inst.Action.Path, claims))
	return adapter.CheckResult{
		Status:        s,
		ValidDuration: h.cacheDuration,
		ValidUseCount: 1000000000,
	}, nil
}

func loadData(p string) ([]byte, error) {
	return []byte(p), nil
}

func parseParam(tokenstringraw string) string {
	tokenstringtrimmed := strings.Trim(tokenstringraw, " ")
	tokenstring := strings.Replace(tokenstringtrimmed, "Bearer ", "", 1)
	return tokenstring
}

func parseToken(tokenString string, key []byte) (bool, jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return key, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return ok, claims, nil
	}
	return false, nil, err

}

func (h *handler) Close() error {
	h.closing <- true
	close(h.closing)

	<-h.done
	return h.f.Close()
}

func (b *builder) SetAdapterConfig(cfg adapter.Config) {
	b.adapterConfig = cfg.(*config.Params)
}

func (b *builder) Validate() (ce *adapter.ConfigErrors) {
	if _, err := filepath.Abs(b.adapterConfig.FilePath); err != nil {
		ce = ce.Append("file_path", err)
	}
	return
}

// GetInfo returns the adapter.Info specific to this adapter.
func GetInfo() adapter.Info {
	return adapter.Info{
		Name:        "jwtcheck",
		Impl:        "istio.io/istio/mixer/adapter/jwtcheck",
		Description: "jwtcheck",
		SupportedTemplates: []string{
			authorization.TemplateName,
		},
		NewBuilder: func() adapter.HandlerBuilder { return &builder{} },
		DefaultConfig: &config.Params{
			CacheDuration: 60 * time.Second,
		},
	}
}
