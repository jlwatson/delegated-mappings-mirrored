---
title: Delegated Authenticated Mappings
abbrev: Delegated Mappings
docname: draft-watson-dinrg-delmap-00
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
    email: colinman@cs.stanford.edu
    street: 353 Serra Mall
    city: Stanford, CA 94305
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
  RFC4506:
  Trillian:
    title: "Trillian: General Transparency"
    author: 
      -
        org: Google
    target: https://github.com/google/trillian

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
  PBFT:
    title: Practical Byzantine Fault Tolerance
    author:
      -
        ins: M. Castro
        name: Miguel Castro
        org: MIT
      -
        ins: B. Liskov
        name: Barbara Liskov
        org: MIT
    target: http://pmg.csail.mit.edu/papers/osdi99.pdf
    date: 1999

--- abstract

Authoritative mappings are commonplace (DNS resolution, TLS certificates, etc.)
but centrally served and lack a common interface. This draft specifies a
generalized scheme for authenticating mappings with a structure that explicitly
supports delegation. The resulting data is secured through any general purpose
distributed consensus protocol; clients may query the local state of any number
of participants and receive the correct result barring a compromise of the
consensus layer.

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

<!-- I wonder if it would be useful to talk about the kinds of mappings we can do
and then kinds that wouldn't really make sense with our system. We rely on some kind of
inherent relationship between the lookup key and the authority (i.e. from the lookup key: 
DNS name, IP prefix, etc., we can determine the authority that can "delegate" that section)
For lookups where there is no such correlation (for example, looking up CA certs), it's not clear
how we would be able to trace throught the table to find the particular CA given a domain
lookup key. This seems like a limitation that we should highlight (or I might be missing something)
-->
Presented in this draft is a generalized mechanism for authenticating and
managing such mappings. Specifically, we describe the structure for a
distributed directory with explicit support for delegation. Certain known
entities are assigned namespaces, loosely associated with a service provided by
that entity (i.e domain prefixes for DNS Authorities). Under that namespace,
are authorized to create mapping records, or _cells_, a unit of ownership in
the service. A namespace's cells are grouped into a logical unit we term a
_table_.

Table cells may also explicitly document the delegation of a portion of the
authority's namespace to another entity with a given public key, along with a
guarantee on that delegation's lifetime. Each delegation forms a new table, for
which the delegee is the sole authority. Thus, the delegating entity may not
make modifications to a delegated table and need not be trusted by the delegee.
The namespace segment may be further delegated to others.

The delegation trees maintain security and consistency through a distributed
consensus algorithm. When a participant receives an update, they verify and
submit it to the consensus layer, after which, if successful, the change is
applied to its associated table. Clients may query any number of trusted
servers and expect the result to be correct barring widespread collusion.

The risk of successful attacks on this system vary based on the consensus
scheme used. Detailed descriptions of specific protocol implementations are out
of scope for this draft, but at a minimum, the consensus algorithm must apply
mapping updates in a consistent order, prevent equivocation or unauthorized
modification, and enforce the semantic rules associated with each table. We
find that federated protocols such as the Stellar Consensus Protocol
{{I-D.mazieres-dinrg-scp}} are promising given their capability for open
participation, broad diversity of interests among consensus participants, and
a measure of accountability for submitting deceptive updates. 

This document specifies the structure for authenticated mapping management and
its interface with a consensus protocol implementation.

# Structure

Trust within the delegation structure is solely based on public key signatures.
Namespace authorities must sign any mapping additions, modifications,
delegations, and revocations as proof to the other consensus participants that
such changes are legitimate. For the sake of completeness, the public key and
signature types are detailed below. All types in this draft are described in
XDR [RFC4506].

~~~
    typedef publickey opaque<>; /* Typically a 256 byte RSA signature */

    struct signature {
        publickey pk; 
        opaque data<>;
    };
~~~

## Cells

Cells are the basic unit of the delegation tree. In general, they define an
authenticated mapping record that may be queried by clients. We describe two
types of cells:

~~~
    enum celltype {
        VALUE = 0,
        DELEGATE = 1
    };
~~~

Value cells store individual mapping entries. They resolve a lookup key to an
arbitrary value, for example, an encryption key associated with an email
address or a the address of an authoritative nameserver for a given DNS zone.
The public key of the cell's owner (e.g. the email account holder, the zone
manager, etc.) is also included, as well as a signature authenticating the
current version of the cell. The cell must be signed either by the `owner_key`,
or in some cases, the authority of the table containing the cell, as is
described below. The cell owner may rotate their public key at any time by
signing the transition with the old key.

~~~
    struct valuecell {
        opaque value<>;
        publickey owner_key;
        signature transition_sig; /* Owner or table authority */
    };
~~~

Delegate cells have a similar structure but different semantics. Rather than
resolving an individual mapping, they authorize the delegee to create arbitrary
value cells within an assigned namespace. This namespace must be a subset of
the _delegator_'s own namespace range. The delegee is identified by their
public key. Finally, each delegate cell and subsequent updates to the cell are
signed by the delegator - this ensures that the delegee cannot unilaterally
modify its namespace, which limits the range of mappings they can legitimately
create.

~~~
    struct delegatecell {
        opaque namespace<>;
        publickey delegee;
        signature authority_sig;  /* Delegator only */
    };
~~~

Both cell types share a set of common data members, namely a set of UNIX
timestamps recording the creation time and, if applicable, the time of last
modification. They are useful indicators and will likely be useful in updating
consensus nodes that have fallen behind.

An additional "commitment" timestamp must be present in every mapping. It is an
explicit guarantee on behalf of the authority creating the cell that the
mapping will remain valid until at least the specified time. Therefore, while
value cell owners may modify their cell at any moment, the authority cannot
successfully change (or remove) the cell until its commitment expires.
Similarly, delegated namespaces are guaranteed to be valid until the commitment
timestamp. This creates a tradeoff between protecting delegees from arbitrary
delegator action and allowing simple reconfiguration that can be customized for
the use case.

~~~
    union innercell switch (celltype type) {
    case VALUE:
        valuecell vcell;   
    case DELEGATE:
        delegatecell dcell;
    };

    struct cell {
        unsigned hyper create_time;     /* 64-bit UNIX timestamps */
        unsigned hyper *revision_time; 
        unsigned hyper commitment_time;
        innercell c;
    }
~~~

## Tables

Every cell is stored in a table, which groups all the mappings created by a
single authority public key for a specific namespace. Individual cells are
referenced by an application-specific label in a lookup table. Below, we allow
for a single lookup key to reference a list of cells, for the sake of
generality. The combination of a lookup key and a referenced cell value forms
an _authenticated mapping_.

~~~
    struct tableentry {
        opaque lookup_key<>;
        cell cells<>;
    }
~~~

Delegating the whole or part of a namespace requires adding a new lookup key
for the namespace in question and a matching delegate cell. Each delegation
must be validated in the context of the other table entries and the table
itself. For example, it should not be possible for the owner of a /8 IPv4 block
to delegate the same /16 block to two different delegees. In addition to a
collection of entries, each table incorporates a "type" that informs each
participating node of the particular delegation rules to apply to table
entries.

~~~
    struct table {
        tabletype type;
        tableentry entries<>;
    };
~~~

While there exist more delegation mechanisms than we could reasonably discuss
in this draft, we initially propose three general-purpose schemes that cover
the majority of use cases:

~~~
    enum tabletype {
        PREFIX = 0,
        SUFFIX = 1,
        FLAT = 2
    };
~~~
<!-- Should we talk about how the type is used? (in consensus layer or in lookup),
at which layer? -->

Prefix-based delegation, such as in an IP delegation use case, requires every
table cell value to be prefixed by the table namespace, and no cell value can
be a prefix of another cell value. Similar rules apply to suffix-based
delegation. In cases where arbitrary values may be mapped (e.g. account names
for an email service provider), "flat" delegation rules are used.

## Root Key Listing

Each delegation tree, one per namespace, is rooted by a public key stored in a
flat root key listing, which is the entry point for lookup operations. Well-known application identifier strings denote the
namespace which they control; the associated namespace root keys form the
starting point for lookups. We describe below how lookups can be accomplished
on the delegation trees.

~~~
    struct rootentry {
        publickey namespace_root_key;
        string application_identifier<>;
        signature listing_sig;
    }

    struct rootlisting {
        rootentry roots<>;
    }
~~~

A significant open question is how to properly administer entries in this
listing, since a strong authority, such as a single root key, can easily
protect the listing from spam and malicious changes, but raises important
concerns about censorship resilience and potential compromise. A federated
approach to management is more in line with the spirit of this draft but opens
the door for counter-productive participation. In the `rootentry` description
above, we allow for either a root signing key to authenticate mappings, or
first-come-first-served self-signed entries. In either case, no more than one
key may control the namespace for a specific application identifier.

## Data Structure

<!-- Change all instances of delegation tree to delegation table? Seems more
consistent with the rest of the draft -->
Delegation trees are stored in a Merkle hash tree, described in detail in
{{RFC6962}}. In particular, it enables efficient lookups and logarithmic proofs
of existence in the tree, and prevents equivocation between different
participants. Specifically, we can leverage Google's {{Trillian}} Merkle tree
<!-- I think CT is not built on top of Trillian, though Trillian is meant
 to be a more general version of CT -->
implementation -- on top of which Certificate Transparency is built -- in map 
mode, which manages arbitrary key-value pairs at scale. This requires
flattening the delegation trees such that each table may be looked up, while
ensuring that a full lookup from the application root be made for each mapping.
Given a `rootentry`, the corresponding table in the Merkle tree can be found
with this concatenation:

~~~
 root_table_name = app_id || namespace_root_key
~~~

Similarly, tables for delegated namespaces are found at:

<!-- If I understand correctly, the table itself has to be a Merkle tree,right?
So there are a bunch of trees for each table and then one big tree that brings all
the trees together. Would it be a good idea to separate the Merkle part from the 
lookup part? Could we build the meta-tree with just a `delegee_public_key` to 
`delegee_table_hash` mapping?
-->
~~~
 root_table_name || delegee_key_1 || ... || delegee_key_n
~~~

Consensus is performed on the Merkle tree containing the flattened collection
of tables.

# Consensus

Safety is ensured by reaching distributed consensus on the state of the tree.
The general nature of a Merkle tree as discussed in the previous section
enables almost any consensus protocol to support delegated mappings, with
varying guarantees on the conditions under which safety is maintained and
different trust implications. For example, a deployment on a cluster of nodes
running a classic Byzantine Fault Tolerant consensus protocol such as {{PBFT}}
requires a limited, static membership and can tolerate compromises in up to a
third of its nodes. In comparison, proof-of-work schemes including many
cryptocurrencies have open membership but rely on economic incentives and
distributed control of hashing power to provide safety, and federated consensus
algorithms ({{I-D.mazieres-dinrg-scp}}) combine dynamic members with real-world
trust relationships but require careful configuration. Determining which
scheme, if any, is the "correct" protocol to support authenticated delegation
is an open question.

## Validation

Incorrect (potentially malicious) updates to the Merkle tree should be rejected
by nodes participating in consensus. Given the limited set of delegation
schemes presented in the previous section, each node can apply the same
validation procedure without requiring application-specific knowledge. Upon any
modification to the tree -- addition of a new root entry, table or cell, or
modification of an existing cell -- the submitted change to the consensus layer
should contain:

<!-- Should we define valid operations? i.e. add entry, remove entry, 
change key (would this require duplicating a table if it is delegee key? 
if yes, should we add a duplicate operation instead?) -->

(1) the updated or newly-created table, and

(2) a Merkle proof containing all the hashes necessary to validate the new root
tree hash.

Finally, each node participating in consensus must confirm before voting for the
update that:

(1) the Merkle proof is correct, and

(2a) an addition to the root key listing is correctly signed by an authorized
party, or

<!-- maybe we should split this section into delegee/value cells to be extra clear? -->
(2b) a new delegation is correctly authenticated, consists of a valid namespace
value owned by the delegator, follows the table-specific delegation rules, and
creates an empty table at the correct key in the tree, or
<!-- Or if there is a collision (determined by table type)? (with either value cell or delegee cell)-->

(2c) a new value cell is correctly authenticated and belongs to the signing
authority's namespace, and has no conflicts in its table, or

(2d) a cell update is properly authenticated and, if proposed by the table
authority, has an expired commitment timestamp.

Only after a round of the consensus protocol is successful are the changes
exposed to client lookups.

# Security Considerations

The security of the delegation trees is primarily tied to the safety properties
of the underlying consensus layer. Further, incorrect use of the public key
infrastructure authenticating each mapping or compromise of a namespace root
key can endanger mappings delegated by the key after their commitments expire.

--- back

# Acknowledgments
{:numbered="false"}

We are grateful for the contributions and feedback on design and applicability
by David Mazieres, as well as help and feedback from the IRTF DIN research
group, including Dirk Kutscher and Melinda Shore.

This work was supported by The Stanford Center For Blockchain Research.

