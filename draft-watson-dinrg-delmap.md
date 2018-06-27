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
    email: colinman@stanford.edu
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

The delegation tree maintains security and consistency through a distributed
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

This document specifies the structure of the delegation tree and its
interface with a consensus protocol implementation.

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
described below. The cell owner may validate any modifications to the cell's
value or rotate their public key at any time by signing the transition with the
old key.

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
        publickey *delegee;
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

Prefix-based delegation, such as in an IP delegation use case, requires every
table cell value to be prefixed by the table namespace, and no cell value can
be a prefix of another cell value. Similar rules apply to suffix-based
delegation. In cases where arbitrary values may be mapped (e.g. account names
for an email service provider), "flat" delegation rules are used.

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

# Security Considerations

TODO

--- back

# Acknowledgments
{:numbered="false"}

TODO

