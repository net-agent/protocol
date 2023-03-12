package utils

import (
	"io"
	"log"
	"time"
)

func LinkReadWriter(dist, src io.ReadWriter) (distReaded, distWritten int64, retErr error) {
	errChan := make(chan error, 2)

	go func() {
		var err error
		distReaded, err = io.Copy(dist, src)
		errChan <- err
	}()

	go func() {
		var err error
		distWritten, err = io.Copy(src, dist)
		errChan <- err
	}()

	// 等待第一个错误返回
	err := <-errChan

	// 等待第二个错误返回，1秒内不返回则忽略
	select {
	case <-errChan:
	case <-time.After(time.Second * 1):
	}

	if err != nil && err != io.EOF {
		retErr = err
	}

	return
}

func LinkAndLog(addr string, dst, src io.ReadWriter) {
	start := time.Now()
	rn, wn, err := LinkReadWriter(dst, src)
	elapse := time.Since(start)

	log.Printf("complete. live='%v' r='%v' w='%v' addr='%v', err='%v'\n",
		elapse, ByteUnit(uint64(rn)), ByteUnit(uint64(wn)), addr, err)
}
