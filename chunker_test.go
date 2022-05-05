package chunker

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"math/rand"
	"testing"
	"time"
)

func parseDigest(s string) []byte {
	d, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return d
}

type chunk struct {
	Length uint
	CutFP  uint64
	Digest []byte
}

// Generated with:
//  fmt.Printf("{%d, 0x%x, parseDigest(\"%s\")},\n", chunk.Length, chunk.Cut, hex.EncodeToString(hashData(chunk.Data)))
//
// created for 32MB of random data out of math/rand's Uint32() seeded by
// constant 23
//
// chunking configuration:
// window size 64, avg chunksize 1<<20, min chunksize 1<<19, max chunksize 1<<23
var chunks1 = []chunk{
	{1533447, 0x6408246850248eec, parseDigest("eb6d234c3c0184bd1df2d1b6f38ff4afbd91ae9752d1ab1bf33d797c9c86b6c7")},
	{654826, 0x46120420502c817e, parseDigest("5e6d690efaafc42fb8ad324115fe1db8e2cababe324b7001b6048256563d00a2")},
	{1125034, 0x98e520689004070a, parseDigest("36ab1f5d4930991d02f6991d2fd7217c78866d2c8bd2f83e62445d032219903d")},
	{1341849, 0xa8e42200080c8da9, parseDigest("efa6a808db7df1d2a6b06a774a180243a72ad68e4e068e322166da8bcdd3beda")},
	{783684, 0xb168002808088d5a, parseDigest("e0c07c415b4301a4c4aee6f904cdef37cfeb5499361a6d24e0c33ff4f7650c89")},
	{897808, 0x6ea5002020248d20, parseDigest("d13b3e64862b074d46b882fc5b6caa2274e6cbf14129e1a995015634fad755e7")},
	{2287888, 0x7bce046090880358, parseDigest("a649a9026fe22c3a819d536918aee1d0fd487df79d2112422504732171aa86d2")},
	{1110971, 0x82f4066030040beb, parseDigest("77c47f77fb970456fd94327b2efe683f3a7782828e4fccbeb928d7612001f99b")},
	{1190302, 0xd072248890a48823, parseDigest("d3112ca30c7d2bb015be7af1379782b79b22b62a14b89c38ab5451b74f7e562a")},
	{2918017, 0x5ebf2660b0280382, parseDigest("22a16eff10e65daf1be3f044190f32b6f33db35feb7c8eda5d2533a1f8456dc9")},
	{962788, 0x1eb2048e0a88a8d, parseDigest("87f29f74974bb5dd62a253b73b3784d3655539b294cefb2995547b569dd143f2")},
	{1009244, 0x8f6202c8c0a4892d, parseDigest("5c379069bf8ef03b9516f9886711d450ef274eded70c4e4bd01d710dc2d62c7c")},
	{1228883, 0xfa5b00a8400c03e8, parseDigest("47966940fb38508a65740a313da5de873ff7b73a86ece4a9b8063f8c03f19e87")},
	{1243579, 0x4eff24c8d0280060, parseDigest("838b0297d6d9bbe6faad71f6a58611d814730f2194251c336ad6a0af330fae83")},
	{634382, 0xff2c004080000057, parseDigest("aac76e336b76c6103fd06fa117817a763827b43c280e40e0fa54b6c45a4c9df3")},
	{1445786, 0x89932220508c84dd, parseDigest("91aa5f670732c703cbdc8b3277cd9aa86619c6bb52cf90caa1a1c6db51ba3a84")},
	{1102384, 0xf67a228038a4075a, parseDigest("9612a9a2a441bb14c9f24bbd08661b60a8ed9b04c22d365417566430ac0d3c8b")},
	{5924013, 0x7e70008868a08f2e, parseDigest("d2a8e28b50175f5bd6755aea989cba7e8682e4313b0f990b13aa84b99d025f68")},
	{1340617, 0xa14200a880048da1, parseDigest("4adfd5c1661dbba28dcf56bf41ab455f484c7fb7b7138df1e462ca541dd128ea")},
	{666322, 0xa3a2260308c853f, parseDigest("f0974d2ea2fa95cc66d172697868a666441574ff872fac9ce60c833e0c9c1c98")},
	{1142810, 0xe82f24e0d0808866, parseDigest("846049f7d7ccd3b922d4560558586bfe045c4b1b0cd955722090d98e322413b9")},
	{1419886, 0xd1f900c8a0a4039f, parseDigest("0283087bebbe5304fee21cc2337d4708d363b378dca59e778dd05477fbaa2a49")},
	{622436, 0x21e70280b0800a87, parseDigest("509772e134fdb4201f21bd6b512a35d26c2b36a8ad2219eb7f29a85b52ae6eb4")},
	{967476, 0x0, parseDigest("5ccfdcd35ec62b4c7e79f31e967bc2554835f59373b38e0b5542a4a2c9d6f888")},
}

// test if nullbytes are correctly split, even if length is a multiple of MinSize.
var chunks2 = []chunk{
	{8388608, 0x0, parseDigest("2daeb1f36095b44b318410b3f4e8b5d989dcc7bb023d1426c492dab0a3053e74")},
}

// the same as chunks1, but avg chunksize is 1<<19
var chunks3 = []chunk{
	{1263430, 0x280940ad13280000, parseDigest("93fba4233a0028eb60e98950107d2dec949d8ddd59ca12670999720e64dfc063")},
	{1178839, 0x17a6e45727300000, parseDigest("64a3f850028d4e70b95697a3a7dcbc67b7e7369147e8bbcdd5ebc21c845cb815")},
	{811643, 0x103e05a705e80000, parseDigest("4228c606d657918d9388dfae32706d952b8858000e5dff846878b8233bdbe797")},
	{1365787, 0xf86586b40a200000, parseDigest("5b27675816ba56538ff7d7a2a4a81706392e7a38b3b2bf24f075921172f4f618")},
	{749466, 0x16686e80bb680000, parseDigest("ae2929ab767e7865e81437f536abf52e43837af1d91dfec477fbc65f0dcb0876")},
	{2131655, 0x41af946ddb500000, parseDigest("101db5112cbfbdf802b45f01deb11801c214c7d9725ca063151d73879d2b5002")},
	{1310162, 0xf862ff0807500000, parseDigest("f4589bbb2d08d7f0bffdc57bc88913918c01b750b2b1d976e0bab9aeb088a6ea")},
	{946703, 0x29e2c581d2c80000, parseDigest("265df03365520a48a874168dbb7d128439564dc7d4e80e72294154df25caf01f")},
	{755920, 0xe86c2188cd080000, parseDigest("72cf7d8ce0b92d477f57d0ee825e8870f17714b49d4cf01c3b9be3686f76676b")},
	{1234986, 0x12d47d9b8ae00000, parseDigest("893de5ddcba940b483bbb40c3e658fdbf88dcd697d692038cafbe19b3693fd0c")},
	{1001836, 0xd80a9a6eb6600000, parseDigest("c2b521e123c035bedf94af6f49ac78630754b43806b1a518e2df81757ac5e22e")},
	{1208245, 0x9d9038a962680000, parseDigest("250ab9e2f717a79fc5684d79fd6efd811b96f5d796d35ae10dc1d89eed334930")},
	{1660090, 0xf1162448900004e7, parseDigest("25fbfb8c0fd5c79f871ab77fd6f9df6c7c55f5536b957480cd2e3dd4cf1f7914")},
	{1236204, 0x1d08ec4c53580000, parseDigest("0098745012da36fe50ebd5d323aafe56600c1e6306b91a872f3c184a77f3eb62")},
	{1005976, 0x8f66292c20b00000, parseDigest("c24a30eac18ad106d2cdc6f819a0e77ff79067dd112d9c79d521d11f2a80ae47")},
	{1651409, 0xd916246810848a33, parseDigest("0784c11b2bd535f912823cf4940b5222c50eb5b4242e68a8f78dbcefc35cabb1")},
	{750787, 0x4a1fabfa8ef80000, parseDigest("7f07502445c3bbd9ac2fe18dcd955f7a024338c4eaf3fa02c7a00a03895855a5")},
	{945985, 0x863d7abbecb80000, parseDigest("45895861147cf8f0389dc26fe1ff7596adfba63a85b0d0214c1a819ab47ce2a0")},
	{1086697, 0xaae9b1ae91100000, parseDigest("9b19e59ec4987ee7ea16f13edb61010c7d16e5efea9b9ec90464f6059f881a53")},
	{1130496, 0x7125267293d00000, parseDigest("ed5c6a5911effd617899b62fa7ad94fb43e8c6b8c18eb7fc6693c220e452f45e")},
	{1952402, 0x898bacee30680000, parseDigest("287f862b03f0e768c4e0aa82ae338957656221d5974c5f51676336e388d5bbbf")},
	{2358615, 0xab4e015b1180000, parseDigest("fdedf3c47e8d41050c9331947b676a9d46a9d64da19e06288c63f5ad711a9fb2")},
	{736962, 0xc046c98dd7b80000, parseDigest("35857dd6edeaf59cff866337f1923aa00e0bfd096768023b1d0a92eb6833de30")},
	{2172902, 0xd3b37d53f0200000, parseDigest("eebb5bb5fd57de7c9178289fc062876ec47bd854ff96db831be0dbb882d1e018")},
	{861626, 0xa125b5e0f9800000, parseDigest("34af925b5e32e7ef733f5e68a800cf3c52d387b43ad6fb1e25af223abe12ee25")},
	{1105988, 0xff7433e7ddd00000, parseDigest("2717a9393158a027b74bfb1991c7b0e6b181699068548e01ecbec1638c452bfd")},
	{939621, 0x0, parseDigest("d28d4a082720b8af62d26076515560bb5474cac5330ca6601859b351bde25e65")},
}

func testWithData(t *testing.T, chnker *Chunker, testChunks []chunk, checkDigest bool) []Chunk {
	chunks := []Chunk{}

	pos := uint(0)
	for i, chunk := range testChunks {
		c, err := chnker.Next(nil)

		if err != nil {
			t.Fatalf("Error returned with chunk %d: %v", i, err)
		}

		if c.Start != pos {
			t.Fatalf("Start for chunk %d does not match: expected %d, got %d",
				i, pos, c.Start)
		}

		if c.Length != chunk.Length {
			t.Fatalf("Length for chunk %d does not match: expected %d, got %d",
				i, chunk.Length, c.Length)
		}

		if c.Cut != chunk.CutFP {
			t.Fatalf("Cut fingerprint for chunk %d/%d does not match: expected %016x, got %016x",
				i, len(chunks)-1, chunk.CutFP, c.Cut)
		}

		if checkDigest {
			digest := hashData(c.Data)
			if !bytes.Equal(chunk.Digest, digest) {
				t.Fatalf("Digest fingerprint for chunk %d/%d does not match: expected %02x, got %02x",
					i, len(chunks)-1, chunk.Digest, digest)
			}
		}

		pos += c.Length
		chunks = append(chunks, c)
	}

	_, err := chnker.Next(nil)
	if err != io.EOF {
		t.Fatal("Wrong error returned after last chunk")
	}

	if len(chunks) != len(testChunks) {
		t.Fatal("Amounts of test and resulting chunks do not match")
	}

	return chunks
}

func getRandom(seed int64, count int) []byte {
	buf := make([]byte, count)
	rnd := rand.New(rand.NewSource(seed))
	_, err := rnd.Read(buf)
	if err != nil {
		panic(err)
	}
	return buf
}

func hashData(d []byte) []byte {
	h := sha512.New512_256()
	h.Write(d)
	return h.Sum(nil)
}

func TestChunker(t *testing.T) {
	// setup data source
	buf := getRandom(23, 32*1024*1024)
	ch := New(bytes.NewReader(buf))
	testWithData(t, ch, chunks1, true)

	// setup nullbyte data source
	buf = bytes.Repeat([]byte{0}, len(chunks2)*MaxSize)
	ch = New(bytes.NewReader(buf))
	testWithData(t, ch, chunks2, true)

}

func TestChunkerWithCustomAverageBits(t *testing.T) {
	buf := getRandom(23, 32*1024*1024)
	ch := New(bytes.NewReader(buf))

	// sligthly decrease averageBits to get more chunks
	ch.SetAverageBits(19)
	testWithData(t, ch, chunks3, true)
}

func TestChunkerReset(t *testing.T) {
	buf := getRandom(23, 32*1024*1024)
	ch := New(bytes.NewReader(buf))

	testWithData(t, ch, chunks1, true)

	ch.Reset(bytes.NewReader(buf))
	testWithData(t, ch, chunks1, true)
}

func TestChunkerWithRandomPolynomial(t *testing.T) {
	// setup data source
	buf := getRandom(23, 32*1024*1024)

	start := time.Now()
	ch := New(bytes.NewReader(buf))
	t.Logf("creating chunker took %v", time.Since(start))

	// make sure that first chunk is different
	c, err := ch.Next(nil)
	if err != nil {
		t.Fatal(err.Error())
	}

	if c.Cut == chunks1[0].CutFP {
		t.Fatal("Cut point is the same")
	}

	if c.Length == chunks1[0].Length {
		t.Fatal("Length is the same")
	}

	if bytes.Equal(hashData(c.Data), chunks1[0].Digest) {
		t.Fatal("Digest is the same")
	}
}

func TestChunkerWithoutHash(t *testing.T) {
	// setup data source
	buf := getRandom(23, 32*1024*1024)

	ch := New(bytes.NewReader(buf))
	chunks := testWithData(t, ch, chunks1, false)

	// test reader
	for i, c := range chunks {
		if uint(len(c.Data)) != chunks1[i].Length {
			t.Fatalf("reader returned wrong number of bytes: expected %d, got %d",
				chunks1[i].Length, len(c.Data))
		}

		if !bytes.Equal(buf[c.Start:c.Start+c.Length], c.Data) {
			t.Fatalf("invalid data for chunk returned: expected %02x, got %02x",
				buf[c.Start:c.Start+c.Length], c.Data)
		}
	}

	// setup nullbyte data source
	buf = bytes.Repeat([]byte{0}, len(chunks2)*MinSize)
	ch = New(bytes.NewReader(buf))

	testWithData(t, ch, chunks2, false)
}

func benchmarkChunker(b *testing.B, checkDigest bool) {
	size := 32 * 1024 * 1024
	rd := bytes.NewReader(getRandom(23, size))
	ch := New(rd)
	buf := make([]byte, MaxSize)

	b.ResetTimer()
	b.SetBytes(int64(size))

	var chunks int
	for i := 0; i < b.N; i++ {
		chunks = 0

		_, err := rd.Seek(0, 0)
		if err != nil {
			b.Fatalf("Seek() return error %v", err)
		}

		ch.Reset(rd)

		for ; ; chunks++ {
			_, err := ch.Next(buf)
			if err != nil {
				if err == io.EOF {
					break
				} else {
					b.Fatalf("Unexpected error occurred: %v", err)
					b.FailNow()
				}
			}
		}

	}

	b.Logf("%d chunks, average chunk size: %d bytes", chunks, size/chunks)
}

func BenchmarkChunker(b *testing.B) {
	benchmarkChunker(b, false)
}

func BenchmarkNewChunker(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		New(bytes.NewBuffer(nil))
	}
}
