# Developer Resources

* [Code Contribution Guidelines](https://btcdemoppc/ppcd/tree/master/docs/code_contribution_guidelines.md)

* [JSON-RPC Reference](https://btcdemoppc/ppcd/tree/master/docs/json_rpc_api.md)
  * [RPC Examples](https://btcdemoppc/ppcd/tree/master/docs/json_rpc_api.md#ExampleCode)

* The btcsuite Bitcoin-related Go Packages:
  * [btcrpcclient](https://btcdemoppc/ppcd/tree/master/rpcclient) - Implements a
    robust and easy to use Websocket-enabled Bitcoin JSON-RPC client
  * [btcjson](https://btcdemoppc/ppcd/tree/master/btcjson) - Provides an extensive API
    for the underlying JSON-RPC command and return values
  * [wire](https://btcdemoppc/ppcd/tree/master/wire) - Implements the
    Bitcoin wire protocol
  * [peer](https://btcdemoppc/ppcd/tree/master/peer) -
    Provides a common base for creating and managing Bitcoin network peers.
  * [blockchain](https://btcdemoppc/ppcd/tree/master/blockchain) -
    Implements Bitcoin block handling and chain selection rules
  * [blockchain/fullblocktests](https://btcdemoppc/ppcd/tree/master/blockchain/fullblocktests) -
    Provides a set of block tests for testing the consensus validation rules
  * [txscript](https://btcdemoppc/ppcd/tree/master/txscript) -
    Implements the Bitcoin transaction scripting language
  * [btcec](https://btcdemoppc/ppcd/tree/master/btcec) - Implements
    support for the elliptic curve cryptographic functions needed for the
    Bitcoin scripts
  * [database](https://btcdemoppc/ppcd/tree/master/database) -
    Provides a database interface for the Bitcoin block chain
  * [mempool](https://btcdemoppc/ppcd/tree/master/mempool) -
    Package mempool provides a policy-enforced pool of unmined bitcoin
    transactions.
  * [ppcutil](https://btcdemoppc/ppcutil) - Provides Bitcoin-specific
    convenience functions and types
  * [chainhash](https://btcdemoppc/ppcd/tree/master/chaincfg/chainhash) -
    Provides a generic hash type and associated functions that allows the
    specific hash algorithm to be abstracted.
  * [connmgr](https://btcdemoppc/ppcd/tree/master/connmgr) -
    Package connmgr implements a generic Bitcoin network connection manager.
