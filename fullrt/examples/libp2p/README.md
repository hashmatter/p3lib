## Full Routing Table request and reply with libp2p

This example shows how to use the full routing table protocol between two libp2p
hosts. In this example, a `node_a` sends a message to `node_b` as part of the
protocol `/p3lib/fullrt/0.1`. `node_b` fetches and encodes its current full
routing table and wires it back to `node_a`. `node_a` receives and decodes the
full routing table and prints it. From here, it can proceed with finding locally
the next set of peers to request the full routing table until the content is
resolved.

```

           Node_A                        Node_B
             |                              |
             |   /p3lib/fullrt/1.0 -->      |
             |                                rt := fullrt.GetFullRoutingTable()
             |                              |
             |       <-- []byte(rt)         |     
 print(rt)

```

### Running the example

1) Run `$ make`. 

The main Makefile step will spawn 2 processes - one for `node_a` and another for
`node_b`. The messages will be printed for understanding.


