## Interfaces

### Peer

A peer implements a PKI based identity using libp2p [1] peer interfaces.

```go
import (
	peer "https://github.com/libp2p/go-libp2p-peer"
	pstore "github.com/libp2p/go-libp2p-peerstore"
)

type Peer interface {
	func ID() peer.ID
	func Peerstore pstore.Peerstore
}

```

### Relayer

```go
type Relayer interface {}
```

### Initiator

```go
type Initiator interface {}
```

## References

[1] [libp2p - Modular peer-to-peer networking stack](https://github.com/libp2p)
