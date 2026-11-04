# One committer per VNI group, named by the server

Status: accepted

The mlsbond server is not a member of any VNI group and cannot commit, so it names one member of
each group as its committer: the longest-standing member, which for a new VNI is the host that
subscribed first and created the group. The server hands the committer what is pending (key
packages to add, members to remove, a request to rekey) and the committer bundles all of it into
one commit. When the committer's stream is gone, the server names the next-oldest member, whose
first commit removes the old committer.

## Considered Options

- **Any member may commit, the first commit per epoch wins.** Allowed by MLS and common in
  messengers, but every membership change would make all members race and all but one retry, and
  hosts joining together would cost one epoch, and so one rekey, each.

## Consequences

Hosts subscribing at the same time are added in one commit and cost one rekey. The server's only
state about this is who the committer is, which it can work out again from the member list.
