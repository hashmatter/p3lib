# p3ib-sinkhole specifications

`p3lib-sinkole` is a protocol base on a practical computational Private 
Information Retrieval (CPIR) key value store that aims at offering provable 
privacy to DHT lookup requests.

A sinkhole is a key-value database maintained by a single entity (in the CPIR
construction), which maintains key-value pairs that are also maintained in the
DHT. The difference is that queries to the sinkhole will not leak any
information about the key being queried, even if the sinkhole provider is
malicious. The `p3lib-sinkhole` prtocol combines the scalability, 
decentralization and simplicity of a DHT with the provable security properties 
of a CPIR to offer practical key-value lookups for a DHT setting.

## Protocol overview

**Sinkhole provider registration**: A sinkhole provider registers itself in the
 DHT as a provider of a subset of 
the domain space of the DHT. We call this subset the `suffix-space`.

Considering a DHT where the domain space is 8 bits long (ie. the peer 
ids and content ids have 8 bits) the sinkhole can define its `suffix-space` as
the first 3 bits. This means that the sinkhole will store and provide
anonymously key-value entries that are suffixed in the `suffix-space`. If the
`suffix-space` is, eg, `2dt`, it means that the sinkhole will provide values for
all the `2dtxxxxx` keys in the space. Registering as a valid sinkhole provider 
in this example can be done by issuing a `DHT.provide(2dt00000)` DHT request.

**Sinkhole provider stores key-values upon request**: After the bootstrapping, 
the sinkhole's key-value storage is empty. The service exposes
a RPC for letting users to request the sinkhole provider to store a `cid` that 
can be later retrieved in a privately way by DHT users. The storing request 
includes the `cid` of the resource to store. Upon receiving the request, the 
sinkhole provider issues a DHT lookup to get peer information of providers of 
the given `cid`. The information returned by the DHT refers to the values of
the stored under `cid` key.

**DHT user requests for the providers of a `cid` privately**: If a DHT node
wants to lookup for the providers of a specific `cid` in the DHT without leaking
information to other nodes about the `cid`, she first tries to discover if 
there is a sinkhole providing a storage in the same `suffix-space` as the `cid`
to resolve. This first step is achieved by requesting the DHT for the providers
of `suffix-id`, where the sinkhole provider might have registered itself. Let's
assume the example above and that the user wants to lookup for the `2dt1hjjw` cid.
She would start by requesting the DHT for the providers of `2dt00000`, by
requesting `DHT.provide(2dt00000)`. If the discovery mechanism is successful,
the user will learn about the peerinfo (IP address, pubkey) of the sinkhole
providers that may have the key-value tuple associated with the cid `2dt1hjjw`.
The second phase of the protocol consists of leveraging homomorphic
multiplication of come cryptographic systems (e.g. Paillier) to generate an
encrypted request that can be sent to the sinkhole provider and, while the
sinkhole provider *is not able to decrypt the content of the request* (i.e. the 
`cid` to resolve), it will be able to compute the result over its key-value
database. The result of the computation is encrypted and can only be decrypted
by the requester. Once the user receives the encrypted response from the server,
she can decrypt is using her private key and verify if the provider has stored
the key-value tuple associated with the requested `cid`. Id successful, the user
leveraged both DHT and the sinkhole provider to resolve a list of DHT `cid`
providers while leaking information about its interests to adversaries and
honest curious peers in the DHT.

## Computational PIR and homomorphic multiplication

## Addressing spaces

**suffix-space**: the first `s` bits of the address; The `suffix-space` is the
amount of information a user discloses to the network about the `cid` to
resolve. The level of privacy is inversely proportional to `s`;

**private-space**: the first `p` bits after the `suffix-space`; The
`private-space` refers to the amount of entries in the operator key value store.
The computation overhead for both user and provider is proportional `p`.

**tail-space**: the remainder bits of the address (i.e. `N - (s + p)`);

Each sinkhole provider defines its own parameters for `s` and `p`. These
parameters affect privacy levels offered by a particular sinkhole provider and
the communication and computation overhead of the protocol. The user must know
`s` for the first stage of the protocol (the DHT lookup) and `p` for the second
step of the protocol (the CPIR query). This information may be shared off-band
or transmitted during the protocol.

### Example

Let's consider a DHT addressing domain with 12 bits (ie. both peer IDs and 
`cids` are represented with 12 bits, with 2^12 possible addresses).

A sink provider bootstraps with the following domain spaces as configurations:

```
 suffix-space of 4 bit   eg `(1dsa________)`
 private-space of 6 bits `(1dsaPPPP__)`
 tail-space of 2 bits    `(1dsaPPPPTT)`
```

From these configurations, we can deduce the following:

- The sinkhole will provide the service for keys from `1dsa00000000` to
  `1dsaffffffff`. This defines the amount of information the user leaks during
the protocol, since adversaries and curious users in the DHT network are able to
learn that the `cid` being looked up is one of `1dsa00000000` -
`1dsaffffffff`.

- The size number of rows in the database of the sink provider is `2^p` (64).
  This number also defines the computation required to encrypt the query and
decrypt the result in the user side and the computation required to run the
query in the sinkhole provider side.

- Each row in the database will potentially store `2^t` (4) key-value tuples.

## Threat model, security and privacy guarantees
### Trust in the sinkhole provider

## Sinkhole provider API

- **Query**

```
-> POST /sinkhole/1/query
   [p]byte

<- [p] byte
```

- **Info** returns the configurations if of the provider, namely the
  `suffix-space`, `p` and `t`.

```
-> GET /sinkhole/1/info

<- {suffix-name, p, t}
```


- **Status** returns the sinkhole current status, e.g. list of stored keys,
  number of stored key-value tuples.

```
-> GET /sinkhole/1/status

<- {...}
```

## Future work and orthogonal features

### Decentralized sinkholes
### Incentives


