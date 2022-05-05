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
	// 1954258 89a95495e176188a45278d9be5272c7aa4556340b6011cf6728198c1c537d7f0
	// 567942 3c701b082fb4ad6a141deb83d36cfc6a534617fde4e0d76a14c619809b62fdfe
	// 1853766 c2ce8171581c38f1a1e20ae583e795768e382516a6f2e02a4038a9c2a6360646
}
