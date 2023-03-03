package vmess

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func hex2bytes(str string) []byte {
	b, _ := hex.DecodeString(str)
	return b
}
func uuid2bytes(str string) []byte {
	u, _ := uuid.Parse(str)
	b, _ := u.MarshalBinary()
	return b
}

func TestGenAuthData(t *testing.T) {
	type args struct {
		userid     []byte
		utcTimeBuf []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"case 1", args{nil, nil}, hex2bytes("74e6f7298a9c2d168935f58c001bad88")},
		{"case 2", args{uuid2bytes("00000000-0000-0000-0000-000000000000"), nil}, hex2bytes("74e6f7298a9c2d168935f58c001bad88")},
		{"case 3", args{uuid2bytes("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"), nil}, hex2bytes("c18edfcb9cb56f77f36cad37bb4b527a")},
		{"case 2", args{uuid2bytes("00000000-0000-0000-0000-000000000000"), hex2bytes("0000000000000000")}, hex2bytes("18853b46630a1a19c58b2b26d6753012")},
		{"case 3", args{uuid2bytes("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"), hex2bytes("0000000000000000")}, hex2bytes("e6a23267964edff0a6f7a498b83407cb")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenAuthData(tt.args.userid, tt.args.utcTimeBuf); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenAuthData() = %v, want %v", hex.EncodeToString(got), hex.EncodeToString(tt.want))
			}
		})
	}
}

func TestGenUTCTimeBuffer(t *testing.T) {
	type args struct {
		t     int64
		delta int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"case 1", args{0, 0}, hex2bytes("0000000000000000")},
		{"case 1", args{0x7FFFFFFFFFFFFFFF, 0}, hex2bytes("7fffffffffffffff")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenUTCTimeBytes(tt.args.t, tt.args.delta); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenUTCTimeBuffer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenCmdKey(t *testing.T) {
	type args struct {
		userid []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"default", args{uuid2bytes("00000000-0000-0000-0000-000000000000")}, hex2bytes("5e20f3239545e3f48e0ff445aa7c4c3b")},
		{"default", args{uuid2bytes("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")}, hex2bytes("a035fe56c2625a0133674c173a886c81")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenCmdKey(tt.args.userid); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenCmdKey() = %v, want %v", hex.EncodeToString(got), hex.EncodeToString(tt.want))
			}
		})
	}
}

func TestGenKDFKey(t *testing.T) {
	type args struct {
		key  []byte
		path []string
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			"default case",
			args{
				key: []byte("Demo Key for KDF Value Test"),
				path: []string{
					"Demo Path for KDF Value Test",
					"Demo Path for KDF Value Test2",
					"Demo Path for KDF Value Test3",
				},
			},
			hex2bytes("53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenKDFKey(tt.args.key, tt.args.path...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenKDFKey() = %v, want %v", hex.EncodeToString(got), hex.EncodeToString(tt.want))
			}
		})
	}
}

func BenchmarkGenKDFKey(b *testing.B) {
	key := []byte("Demo Key for KDF Value Test")
	path := []string{
		"Demo Path for KDF Value Test",
		"Demo Path for KDF Value Test2",
		"Demo Path for KDF Value Test3",
	}
	for n := 0; n < b.N; n++ {
		GenKDFKey(key, path...)
	}
}

func TestGenEAuId(t *testing.T) {
	type args struct {
		cmdKey    []byte
		timestamp int64
		rnd       int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"case1", args{nil, 0, 0}, hex2bytes("78a22d60e450d1ea443338f5c97a8822")},
		{"case2", args{nil, 0, 0x7fffffff}, hex2bytes("1ccb4020d9f6f870ddee1db8db52b98b")},
		{"case3", args{nil, 0x7fffffffffffffff, 0}, hex2bytes("8444524d94ef42333c98ae99dcf769e4")},
		{"case4", args{nil, 0x7fffffffffffffff, 0x7fffffff}, hex2bytes("d2d02dab6ee300cee803b3e10b1073c4")},
		{"magic", args{nil, 0, 1947411196}, hex2bytes("04ec54d5e8b75e86721061874e96b9a3")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenEAuId(tt.args.cmdKey, tt.args.timestamp, tt.args.rnd)
			if err != nil {
				t.Errorf("GenEAuId() failed, err=%v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenEAuId() = %v, want %v", hex.EncodeToString(got), hex.EncodeToString(tt.want))
			}
		})
	}
}

func TestCheckEAuId(t *testing.T) {
	id := func() []byte {
		id, err := GenEAuId(nil, 0, 0)
		if err != nil {
			t.Error(err)
			return nil
		}
		return id
	}

	type args struct {
		cmdKey     []byte
		data       []byte
		timestamp1 int64
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"case1", args{nil, id(), 0}, false},
		{"case2", args{nil, id(), 119}, false},
		{"case3", args{nil, id(), 120}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckEAuId(tt.args.cmdKey, tt.args.data, tt.args.timestamp1); (err != nil) != tt.wantErr {
				t.Errorf("CheckEAuId() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAesGcmEncryptDecrypt(t *testing.T) {
	var key [16]byte
	var nonce [12]byte
	var additional [128]byte

	bufs := [][]byte{
		{0x0, 0x0},
		make([]byte, 1024),
	}

	for _, buf := range bufs {
		encoded, err := AesGcmEncrypt(key[:], nonce[:], buf, additional[:])
		assert.Nil(t, err)
		assert.Equal(t, len(buf)+16, len(encoded))

		decoded, err := AesGcmDecrypt(key[:], nonce[:], encoded, additional[:])
		assert.Nil(t, err)
		assert.True(t, bytes.Equal(buf, decoded))
	}
}
