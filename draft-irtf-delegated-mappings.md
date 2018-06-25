---
title: Delegated Distributed Mappings
abbrev: DDM
docname: draft-watson-dinrg-ddm-00
category: exp

ipr: trust200902
area: Internet
keyword: delegation

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: S. Li
    name: Sydney Li
    organization: Electronic Frontier Foundation
    abbrev: EFF
    email: sydney@eff.org
    street: <TODO fill this in>
    city: <TODO fill this in>
    country: US
 -
    ins: C. Man
    name: Colin Man
    organization: Stanford University
    email: colinman@stanford.edu
    street: <TODO fill this in>
    city: <TODO fill this in>
    country: US
 -
    ins: J. Watson
    name: Jean-Luc Watson
    organization: Stanford University
    email: jlwatson@cs.stanford.edu
    street: 353 Serra Mall
    city: Stanford, CA
    country: US

normative:
  RFC2119:

informative:

--- abstract

TODO Come back and finish this after the rest of the document is written.

--- middle

# Introduction

**** copy stuff from our previous presentations and stuffz ****

# Structure

TODO
explain how owners/delegators/authorities are identified by their public key
each authority can make delegations in their _table_, recorded in individual _cells_.

explain use of signature briefly

~~~
typedef publickey opaque[32];

struct signature {
    publickey pk;
    opaque data[32];
};
~~~

## Cells

~~~
/* */
struct valuecell {
    opaque value<>;           /* */
    publickey owner_key;      /* */
    signature transition_sig; /* */
};

/* */
struct delegatecell {
    opaque namespace<>;       /* */
    publickey *delegee;       /* */
    signature authority_sig;  /* */
};

enum celltype {
    VALUE = 0,
    DELEGATE = 1
};

/* */
union cell switch (celltype type) {
case VALUE:
    valuecell vcell;   
case DELEGATE:
    delegatecell dcell;
};
~~~

## Tables

~~~
/* */
enum tabletype {
    PREFIX = 0,
    SUFFIX = 1,
    FLAT = 2
};

/* */
struct tableentry {
    opaque lookup_key<>; /* */
    cell cells<>;        /* */
}

/* */
struct table {
    tabletype type;        /* */
    tableentry entries<>; /* */
};
~~~

## Root Key Listing

~~~
/* */
struct tableentry {
    publickey authority; /* */
    table *delegations;  /* */
}

/* */
struct tables {
    tableentry entries<>; /* */
}
~~~

Adding to the root listing is by ???. No one knows yet.

## Delegation

rules are based on the type of the table, discussed later (below). delegating
the whole or part of a namespace requires adding a new lookup key for the
namespace and a matching delegate cell. The dcell should be created with the
same namespace value, the publickey of the _delegee_, who will control a table for futher sub-delegating the namespace. Finally, the dcell is signed by the table authority publickey to authorize the addition. 

## Merkle Tree

We can use the Trillian implementation _if_ we can uniquely identify tables by
name --> root key + path of keys down to the delegation. Thus, to get to a
table, you have to perform a log-time lookup procedure during which it is
impossible to reach an entry not on the proper chain (hashes of a key chain
should be hard to guess). Also helps us validate delegation during consensus
(discussed later) Thus, the virtual structure (tree of tables) is different
from the actual structure (leaf-only Merkle tree).

On delegation, the change should contain (1) proof (i.e. hash path to root for updated table), (2) the updated table delta, (3) the new table (empty) to add to the tree with the right key.

Then:
* explain how to hash up the tree / get an existence proof
* what do we need to perform consensus? an added/updated cell and the hash path to the root

# Consensus

TODO

## Protocol

## Enforced Transitions

# Representative Use Cases

TODO

## DNS Delegation

## IP Address Delegation

# Security Considerations

TODO

--- back

# Acknowledgments
{:numbered="false"}

TODO

