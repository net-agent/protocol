package vmess

import "io"

func NewChunkReadWriteCloser(
	raw io.ReadWriteCloser,
	wChunk, rChunk *Chunk,
) io.ReadWriteCloser {

	return &ChunkReadWriteCloser{
		Closer:      raw,
		ChunkWriter: NewChunkWriter(raw, wChunk),
		ChunkReader: NewChunkReader(raw, rChunk),
	}
}

type ChunkReadWriteCloser struct {
	io.Closer
	*ChunkReader
	*ChunkWriter
}

//
// Reader
//

func NewChunkReader(r io.Reader, chunk *Chunk) *ChunkReader {
	return &ChunkReader{
		raw:   r,
		cache: chunk,
	}
}

type ChunkReader struct {
	raw io.Reader

	cache       *Chunk
	cacheReaded int
}

func (cr *ChunkReader) Read(buf []byte) (nn int, ee error) {
	// 判断是否所有的缓存数据都已经被读取过了
	if cr.cacheReaded >= cr.cache.DataSize() {
		cr.cacheReaded = 0
		_, err := cr.cache.ReadFrom(cr.raw)
		if err != nil {
			return 0, err
		}
	}

	// 将部分数据拷贝到目标区域中，完成一次Read
	n := copy(buf, cr.cache.Data()[cr.cacheReaded:])
	cr.cacheReaded += n
	return n, nil
}
func NewChunkWriter(w io.Writer, chunk *Chunk) *ChunkWriter {
	return &ChunkWriter{w, chunk}
}

type ChunkWriter struct {
	raw   io.Writer
	chunk *Chunk
}

func (cw *ChunkWriter) Write(buf []byte) (nn int, ee error) {
	return WriteAll(cw.safeWriteFrame, buf, MaxDataSize)
}

func (cw *ChunkWriter) safeWriteFrame(buf []byte) error {
	_, err := cw.chunk.SetData(buf).WriteTo(cw.raw)
	return err
}
