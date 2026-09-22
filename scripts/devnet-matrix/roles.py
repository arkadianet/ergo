#!/usr/bin/env python3
"""What each devnet node is DOING in an experiment (M4, spec §4).

A NODE is a process slot: a port pair, a data directory, a config. A
ROLE is what that slot is doing — which build it runs, and whether it
mines. M3 had one build, so the two were the same thing and the node
name carried both meanings. M4 measures base + single patch against
base, so the same slot runs a different build from one run to the next,
and the experiment has to say WHICH.

This is its own module, not part of `lifecycle`, for an ordering reason:
`campaign.py` resolves a scenario's roles to decide the node set, and
only then sets the port environment `lifecycle` reads AT IMPORT. A role
table inside `lifecycle` would drag that import forward and freeze the
two-node smoke defaults over every campaign scenario.

Two roles share the `scala` slot (`scala_miner` / `scala_miner_patched`)
and two share `scala2` (`scala_miner2` / `scala_follower`): they are
alternatives, never simultaneous, and `campaign.py --self-test` asserts
that every scenario's role set maps ONE-TO-ONE onto its nodes.
"""


class Role:
    """One node's job in an experiment: its slot, its build, its mining."""

    __slots__ = ('name', 'node', 'kind', 'mines', 'patched', 'why')

    def __init__(self, name, node, kind, mines=False, patched=False, why=''):
        self.name = name
        self.node = node
        self.kind = kind
        self.mines = mines
        # A `*_patched` role is the one `campaign.py --build` selects the
        # build for; every other Scala role runs `stock`, so an ablation
        # is always base+one-patch against base.
        self.patched = patched
        self.why = why

    def __repr__(self):
        return f'Role({self.name!r}, node={self.node!r})'


ROLES = {
    'scala_miner': Role(
        'scala_miner', 'scala', 'scala', mines=True,
        why='the stock reference miner; the baseline every patched number '
            'is measured against'),
    'scala_miner_patched': Role(
        'scala_miner_patched', 'scala', 'scala', mines=True, patched=True,
        why='the same slot running the build under test (F11, F4)'),
    'scala_miner2': Role(
        'scala_miner2', 'scala2', 'scala', mines=True,
        why='the second miner the fork and rollback scenarios need'),
    'scala_follower': Role(
        'scala_follower', 'scala2', 'scala',
        why='the STOCK reference follower: the miner generates its blocks '
            'locally, so it never makes the reconstruct-or-download '
            'decision and only a follower produces the reference half of '
            'the ratio'),
    'scala_follower_patched': Role(
        'scala_follower_patched', 'scala3', 'scala', patched=True,
        why='the patched reference follower, on its own slot so it can run '
            'beside the stock one (--reference-follower both)'),
    'rust_follower': Role(
        'rust_follower', 'rust', 'rust',
        why='the port under test; never mines on this devnet'),
}

# The order nodes are started in, and the reverse of the order they are
# stopped in.
NODE_ORDER = ('scala', 'scala2', 'scala3', 'rust')


def role_node(role):
    """The process slot a role runs in."""
    return ROLES[role].node


def roles_for_nodes(roles):
    """`{node: role}` for a role set, refusing two roles in one slot."""
    assigned = {}
    for role in roles:
        if role not in ROLES:
            raise KeyError(f'unknown role {role!r}; have {sorted(ROLES)}')
        node = ROLES[role].node
        if node in assigned:
            raise ValueError(
                f'roles {assigned[node]!r} and {role!r} both want the {node!r} '
                'slot; they are alternatives, not a node set')
        assigned[node] = role
    return assigned


def nodes_for_roles(roles):
    """The node set a role set occupies, in start order."""
    assigned = roles_for_nodes(roles)
    return tuple(n for n in NODE_ORDER if n in assigned)
