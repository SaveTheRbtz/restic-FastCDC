package chunker

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
)

func ExampleChunker() {
	// generate 32MiB of deterministic pseudo-random data
	data := getRandom(23, 32*1024*1024)

	// create a chunker
	chunker := New(bytes.NewReader(data))

	// reuse this buffer
	buf := make([]byte, 8*1024*1024)

	for i := 0; i < 5; i++ {
		chunk, err := chunker.Next(buf)
		if err == io.EOF {
			break
		}

		if err != nil {
			panic(err)
		}

		fmt.Printf("%d %02x\n", chunk.Length, sha256.Sum256(chunk.Data))
	}

	// Output:
	// 1055958 7c03c0ee6d44462f2fbe428b0deeee8e22ffd1cbc3667be4a3be490285af4e04
	// 1140695 8be66a631f798ac2066b334fd67ae908b8266c969c130ea016394491322d326b
	// 2522200 0af6f9843f611bf82bebd275889c1ca1bf38881069f436467c6bdbcc03ffabe0
	// 1853766 c2ce8171581c38f1a1e20ae583e795768e382516a6f2e02a4038a9c2a6360646
	// 2281845 57fb7d3c18a5849bc64d2eeef0c570537952f39046b67522a56ca67efcc22fcb
}
