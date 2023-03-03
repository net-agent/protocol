package vmess

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommand(t *testing.T) {
	cmds := []*Command{
		NewCommand(1, 2, 3, AddressIPv4, []byte{1, 2, 3, 4}, 1234),
		NewCommand(1, 2, 3, AddressIPv6, []byte{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}, 5678),
		NewCommand(1, 2, 3, AddressDomain, []byte("hello.world.com"), 9876),
	}

	for i, cmd := range cmds {
		t.Run(fmt.Sprintf("testcase-%v", i), func(t *testing.T) {
			buf := bytes.NewBuffer(nil)
			cmd.WriteTo(buf)

			cmd2, err := NewCommandFromBuffer(buf.Bytes())
			if err != nil {
				t.Error(err)
				return
			}

			assert.Equal(t, cmd.CommandHeader, cmd2.CommandHeader)
			assert.Equal(t, cmd.addressData, cmd2.addressData)
		})
	}
}
