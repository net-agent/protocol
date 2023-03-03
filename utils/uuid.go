package utils

import "github.com/google/uuid"

func ParseUUID(id string) (userid []byte, err error) {
	u, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}
	userid, _ = u.MarshalBinary()
	err = nil
	return
}
