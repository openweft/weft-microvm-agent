package secretclient

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
)

// FWCfgTokenPath is where the QEMU driver's fw_cfg entry
// opt/org.weft/boot-token appears in the guest (root-only; needs
// CONFIG_FW_CFG_SYSFS or `modprobe qemu_fw_cfg`): exactly TokenLen raw bytes.
const FWCfgTokenPath = "/sys/firmware/qemu_fw_cfg/by_name/opt/org.weft/boot-token/raw"

// FileTokenSource returns a TokenSource that reads the per-boot token from
// path ONCE, on first use, and keeps it in memory only (it is never logged
// or written anywhere). An absent file means the driver provides no token:
// the source yields an empty token. Any other length than TokenLen, or an
// unreadable file, is an error and no token (never a truncated one) is
// sent. The outcome, error included, is remembered: the file is not read
// again.
func FileTokenSource(path string) TokenSource {
	var (
		once sync.Once
		tok  []byte
		err  error
	)
	return func() ([]byte, error) {
		once.Do(func() { tok, err = readToken(path) })
		if err != nil {
			return nil, err
		}
		return tok, nil
	}
}

func readToken(path string) ([]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open boot token: %w", errors.Unwrap(err))
	}
	defer f.Close()
	// one byte more than TokenLen, so an over-long file is seen as such
	b, err := io.ReadAll(io.LimitReader(f, TokenLen+1))
	if err != nil {
		clear(b)
		return nil, errors.New("read boot token failed")
	}
	if len(b) != TokenLen {
		n := len(b)
		clear(b)
		return nil, fmt.Errorf("boot token: want %d bytes, got %d", TokenLen, n)
	}
	return b, nil
}
