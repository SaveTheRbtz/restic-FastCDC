An introduction to Content Defined Chunking can be found in the restic blog
post [Foundation - Introducing Content Defined Chunking (CDC)](https://restic.github.io/blog/2015-09-12/restic-foundation1-cdc).

Now we implement the FastCDC algorithm instead of the original CDC, and we achieve higher speed. 
The paper about FastCDC is [here](https://www.usenix.org/conference/atc16/technical-sessions/presentation/xia)

Even w/o AVX2 it is capable of chunking at ~1.6GiB/s per core.
```
goos: linux
goarch: amd64
pkg: github.com/restic/chunker
cpu: Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz
BenchmarkChunker-8            30          41026913 ns/op        1635.73 MB/s
```