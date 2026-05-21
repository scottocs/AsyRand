module github.com/scottocs/Tyche/spurt

go 1.24.0

require go.dedis.ch/kyber/v3 v3.1.0

require (
	go.dedis.ch/fixbuf v1.0.3 // indirect
	go.dedis.ch/protobuf v1.0.11 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
)

require github.com/scottocs/Tyche/utils v0.0.0

replace github.com/scottocs/Tyche/utils => ../utils
