module github.com/openweft/weft-vm-agent

go 1.25.0

require (
	github.com/nats-io/nats.go v1.52.0
	github.com/openweft/weft-microvm-init v0.0.0-00010101000000-000000000000
	github.com/openweft/weft-proto v0.0.0
	google.golang.org/grpc v1.80.0
)

require (
	github.com/creack/pty v1.1.24 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/nats-io/nkeys v0.4.15 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace (
	github.com/openweft/weft-microvm-init => ../weft-microvm-init
	github.com/openweft/weft-proto => ../weft-proto
)
