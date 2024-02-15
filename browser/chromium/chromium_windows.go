//go:build windows

package chromium

import (
	"encoding/base64"
	"errors"
	"os"

	"github.com/tidwall/gjson"

	"github.com/gvcgo/hackbrowser/crypto"
	"github.com/gvcgo/hackbrowser/item"
	"github.com/gvcgo/hackbrowser/log"
	"github.com/gvcgo/hackbrowser/utils/fileutil"
)

var errDecodeMasterKeyFailed = errors.New("decode master key failed")

func (c *Chromium) GetMasterKey() ([]byte, error) {
	b, err := fileutil.ReadFile(item.TempChromiumKey)
	if err != nil {
		return nil, err
	}
	defer os.Remove(item.TempChromiumKey)

	encryptedKey := gjson.Get(b, "os_crypt.encrypted_key")
	if !encryptedKey.Exists() {
		return nil, nil
	}

	key, err := base64.StdEncoding.DecodeString(encryptedKey.String())
	if err != nil {
		return nil, errDecodeMasterKeyFailed
	}
	c.masterKey, err = crypto.DPAPI(key[5:])
	log.Infof("%s initialized master key success", c.name)
	return c.masterKey, err
}
