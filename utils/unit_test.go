package utils

import "testing"

func TestByteUnit(t *testing.T) {
	const KB = uint64(1024)
	const MB = 1024 * KB
	const GB = 1024 * MB
	const TB = 1024 * GB

	type args struct {
		n uint64
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"B", args{0}, "0B"},
		{"B", args{1}, "1B"},
		{"B", args{1023}, "1023B"},
		{"KB", args{1024}, "1KB"},
		{"KB", args{1025}, "1KB"},
		{"KB", args{1127}, "1.1KB"},
		{"KB", args{2047}, "1.9KB"},
		{"KB", args{2048}, "2KB"},
		{"MB", args{5 * MB}, "5MB"},
		{"GB", args{5 * GB}, "5GB"},
		{"TB", args{5 * TB}, "5TB"},
		{"TB", args{1025 * TB}, "1025TB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ByteUnit(tt.args.n); got != tt.want {
				t.Errorf("ByteUnit() = %v, want %v", got, tt.want)
			}
		})
	}
}
