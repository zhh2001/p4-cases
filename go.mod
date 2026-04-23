module github.com/zhh2001/p4-cases

go 1.25.0

require (
	github.com/p4lang/p4runtime v1.5.0
	github.com/zhh2001/p4runtime-go-controller v1.1.0
)

require (
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/grpc v1.80.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

// While both repositories live side by side for development, the
// controller code pulls the SDK from the local checkout. Remove the
// replace once the SDK is published and tagged on a proxy.
replace github.com/zhh2001/p4runtime-go-controller => /home/howard/p4runtime-go-controller
