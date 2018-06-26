---
title: Delegated Authenticated Mappings
abbrev: Delegated Mappings
docname: draft-li-dinrg-delmap-00
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
    street: 815 Eddy Street
    city: San Francisco, CA 94109
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
    city: Stanford, CA 94305
    country: US

normative:

informative:
  RFC1034:
  RFC6960:
  RFC4880:
  RFC6962:
  RFC4033:
  bin-transparency:
    title: Security/Binary Transparency
    author:
      -
        ins: R. Barnes
        name: Richard Barnes
        org: Mozilla
    target: https://wiki.mozilla.org/Security/Binary_Transparency
    date: 2017
  I-D.mazieres-dinrg-scp:
    title: The Stellar Consensus Protocol (work in progress)
    date: 2018
    author:
      -
        ins: N. Barry
        name: Nicolas Barry
      - 
        ins: G. Losa
        name: Giuliano Losa
      -
        ins: D. Mazieres
        name: David Mazieres
      -
        ins: J. McCaleb
        name: Jed McCaleb
      -
        ins: S. Polu
        name: Stanislas Polu
    target: https://tools.ietf.org/html/draft-mazieres-dinrg-scp-03

--- abstract

TODO Come back and finish this after the rest of the document is written.

--- middle

# Introduction

Internet applications rely heavily on authoritative translation to function
correctly. Typical services might resolve domain mappings using DNS
{{RFC1034}}, verify the validity of X.509 certificates {{RFC6960}}, or send
encrypted email {{RFC4880}}, among others. Serving incorrect and/or malicious
mappings can easily compromise infrastructure security, thus prompting efforts
to secure these mechanisms: Certificate Transparency (CT) {{RFC6962}} for
misissued certificates, DNSSEC {{RFC4033}}, and binary transparency for
verifiable executables {{bin-transparency}}.

Presented in this draft is a generalized mechanism for authenticating and
managing such mappings. Specifically, we describe the structure for a
distributed directory with explicit support for delegation. Certain known
entities are assigned namespaces, loosely associated with a service provided by
that entity (i.e domain prefixes for DNS Authorities).  Under that namespace,
are authorized to create mapping records, or _cells_, a unit of ownership in
the service. A namespace's cells are grouped into a logical unit we term a
_table_.

Table cells may also explicitly document the delegation of a portion of the
authority's namespace to another entity with a given public key, along with a
guarantee on that delegation's lifetime. Each delegation forms a new table, for
which the delegee is the sole authority. Thus, the delegating entity may not
make modifications to a delegated table and need not be trusted by the delegee.
The namespace segment may be further delegated to others.

The directory maintains security and consistency through a distributed
consensus algorithm. When a participant receives an update, they verify and
submit it to the consensus layer, after which, if successful, the change is
applied to its associated table. Clients may query any number of trusted servers and expect the result to be correct barring widespread collusion.

The risk of successful attacks on this system vary based on the consensus
scheme used. Detailed descriptions of specific protocol implementations are out
of scope for this draft, but at a minimum, the consensus algorithm must apply
mapping updates in a consistent order, prevent equivocation or unauthorized
modification, and enforce the semantic rules associated with each table. We
find that federated protocols such as the Stellar Consensus Protocol
{{I-D.mazieres-dinrg-scp}} are promising given their capability for open
participation, broad diversity of interests among consensus participants, and
a measure of accountability for submitting deceptive updates. 

This document specifies the structure of the delgated mapping directory and its
interface with a consensus protocol implementation.

# Structure

TODO
explain how owners/delegators/authorities are identified by their public key
each authority can make delegations in their _table_, recorded in individual _cells_.

explain use of signature briefly

~~~
typedef publickey opaque<>; /* recommend 32 bytes? */

struct signature {
    publickey pk;    /* */
    opaque data<>; /* recommend 256 bytes? */
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

