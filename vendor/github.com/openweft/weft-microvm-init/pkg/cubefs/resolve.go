package cubefs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/openweft/weft-microvm-init/pkg/pod"
	"github.com/openweft/weft-microvm-init/pkg/secretclient"
)

// ResolveTimeout bounds all the fetches of one mount (each fetch retries
// with backoff inside it).
const ResolveTimeout = 60 * time.Second

// Resolve returns spec with its CubeFS keys filled in: a key named by a
// *_ref is fetched over vsock from src; an inline key is kept, with a loud
// warning (inline keys are deprecated and will be refused). A ref set
// together with its inline field is an error. The returned wipe func zeroes
// the fetched buffers; call it once the config is written. spec is not
// modified.
func Resolve(ctx context.Context, spec pod.ShareMount, src secretclient.Source) (pod.ShareMount, func(), error) {
	noop := func() {}
	if spec.CubeFS == nil {
		return spec, noop, nil
	}
	c := *spec.CubeFS
	spec.CubeFS = &c
	if err := c.ValidateSecrets(); err != nil {
		return spec, noop, fmt.Errorf("cubefs %q: %w", spec.ID, err)
	}
	var held []*secretclient.Secret
	wipe := func() {
		for _, s := range held {
			s.Wipe()
		}
	}
	fetch := func(name, ref string, dst *string) error {
		if ref == "" {
			if *dst != "" {
				slog.Warn("inline cubefs key in the mount message is deprecated: use a *_ref secret id (inline will be refused in a future release)",
					"id", spec.ID, "field", name)
			}
			return nil
		}
		if src == nil {
			return errors.New("no secret source configured for " + name + "_ref")
		}
		s, err := src.Fetch(ctx, ref, 0)
		if err != nil {
			return fmt.Errorf("%s_ref: %w", name, err)
		}
		held = append(held, s)
		*dst = strings.TrimSpace(string(s.Value))
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, ResolveTimeout)
	defer cancel()
	if err := fetch("access_key", c.AccessKeyRef, &c.AccessKey); err != nil {
		wipe()
		return spec, noop, fmt.Errorf("cubefs %q: %w", spec.ID, err)
	}
	if err := fetch("secret_key", c.SecretKeyRef, &c.SecretKey); err != nil {
		wipe()
		return spec, noop, fmt.Errorf("cubefs %q: %w", spec.ID, err)
	}
	return spec, wipe, nil
}
