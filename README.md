[![Build Status](https://travis-ci.org/helium/merkerl.svg?branch=master)](https://travis-ci.org/helium/merkerl)
[![Coverage Status](https://coveralls.io/repos/github/helium/merkerl/badge.svg?branch=master)](https://coveralls.io/github/helium/merkerl?branch=master)


merkerl
--------

A library for building and using [Merkle Trees](https://en.wikipedia.org/wiki/Merkle_tree).

Why yet another Merkle Tree implementation? Mostly because other implementations didn't allow for pluggable hash functions, did not support proof generation or verification, tried to support mutable trees, or some combination of the above.


Build
-----

```
    $ make
```

To build documentation:

```
    $ make docs
```


Usage
-----

Construct a merkle tree:

```
    Values = ["foo", "bar", "baz", "dog", "cat", "bear", "plant"],
    Merkle = merkerl:new(Values, fun merkerl:hash_value/1),
```

Generate a proof for a value in a merkle tree:

```
    ValueHash = merkerl:hash_value("bar"),
    Proof = merkerl:gen_proof(ValueHash, Merkle),
```

Verify a proof for a value in a merkle tree:

```
    ok = merkerl:verify_proof(ValueHash, Merkle, Proof),
```

There are other functions for accessing the leaves and values from a
merkle tree. For complete documentation, see the generated docs.
