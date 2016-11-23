# Statistics Interface for PV Drivers/Agents

## Background

It is common for guest PV drivers or agents to communicate statistics to an
agent running in a toolstack domain so that these can be displayed via a UI,
or even influence guest placement etc. The mechanism for conveying these
statistics is currently ad-hoc, undocumented, and usually based on xenstore.

Whilst xenstore does indeed provide a convenient mechanism, the lack of
documentation and standardisation of the protocols used creates
compatibility issues for PV drivers or agents not tied to a specific
product or environment. Also, the guest xenstore quota and the single
instance of xenstored can easily become scalability issues.

## Proposal

The proposed interface is intended to be used only for the purposes of
conveying statistics from guest PV drivers or agents to an agent or agents
running in a toolstack domain. It is not intended for bulk data transfer,
nor as another means of control of the PV drivers or agents by the
toolstack domain.

PV drivers or agents typically publish multiple related sets of statistics.
For example, a PV network frontend may publish statistics relating to
received traffic and transmitted traffic. These sets are likely to be
updated asynchronously from each other and therefore it makes sense that
they can be separated such that a monitoring agent can refresh its view of
them asynchronously. It is therefore proposed that a two-level hierarchy of
xenstore keys is used to advertise sets of guest statistics.

The toolstack will create a writeable top-level `stats` key in the guest
space. Under this each guest statistics *provider* creates a key its name,
e.g. `Network #0`. This key acts as a parent to keys that then name each
set of statistics that it provides, e.g. `Tx`. Under the key for a
particular set the provider then writes entries containing grant references
of pages containing the names and values of the statistics in that set, and
an event channel to be used for signalling e.g.:

    name-type-ref0 = 10
    name-type-ref1 = 11
    val-ref0 = 12
    val-ref1 = 13
    event-channel = 10

The provider must always write the `event-channel` key after all the other
keys have been written such that a monitoring agent with a watch on the
guest's top-level `stats` key can make the assumption that it is safe to
sample all other keys once that key has been written. Thus no explicit
`state` key is required.

There are separate references for pages containing the names and types of
the statistics and the values of those statistics since it is required that
the names and types do not change and hence a monitoring agent need only
sample them once and can do so as soon as the as the `name-ref` keys are
valid. The format of each (*name, type*) tuple is as follows:

    struct stats_name_type {
	uint8_t type;
	char name[63];
    };

and the possible types are:

    #define STATS_TYPE_S64		1
    #define STATS_TYPE_U64		2
    #define STATS_TYPE_DOUBLE	3
    #define STATS_TYPE_ASCII	4

The `name` must be a NUL terminated ASCII string containing only
alphanumeric characters, printable non-alphanumeric characters or a space
character, i.e. the expression:

    (isalnum(name[i]) || ispunct(name[i]) || name[i] == ' ')

must be true for each value of `i` until `name[i] == '\0'`

When iterating through the `stats_name_type` structures a monitoring agents
can determine that it has finished when it either encounters a `type` value
of 0, or it has iterated through all 64 structures in the granted page and
there are no further `name-type-ref` keys.

A monitoring agent can find the value of a statistic by noting the
`name-type-ref` index and the offset into the page where the
`stats_name_type` was found and the looking at the same offset in the
corresponding `val-ref` page. Values are therefore also 64 octets
in length and contain:

* `STATS_TYPE_S64` : A signed 64-bit integer in little endian form in
		     octets 0..7
* `STATS_TYPE_U64` : An unsigned 64-bit integer in little endian form in
		     octets 0..7
* `STATS_TYPE_DOUBLE` : A double precision floating point value in little
			endian form in
			octets 0..7
* `STATS_TYPE_ASCII` : A NUL terminated ASCII string meeting the same
		       criteria as `name`

A statistics provider should not update any of the statistics in a set
until the `event-channel` is signalled indicating that a monitoring agent
wishes to sample them. Thus the rate of update is nominally under control
of the monitoring agent.

When such a signal is received, all statistics in the set should then be
updated and a signal set back to the monitoring agent via the
`event-channel` to say that the update is complete. The monitoring agent
can then sample the whole set, knowing that it is self-consistent, as long
as the provider is not misbehaving.

When a provider wishes to withdraw a set of statistics, e.g. when it is
shutting down, it notifies a monitoring agent by deleting the
`event-channel` key from xenstore. Thus a monitoring agent must maintain a
watch on that key and respond in a timely manner by closing its port. Once
the provider detects that channel is no longer bound then it can remove the
whole set of keys corresponding to the set. When the provider is no longer
advertising any sets it can then remove its top-level key.
