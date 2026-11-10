# OneNote (.one) support: kill-criterion decision

Status: NOT IMPLEMENTED beyond format identification. This
document is the decision record the v5 research required.

The research set a kill criterion for OneNote Tier 2: a
spec-conformant fixture writer must exist before any parser
ships, because a parser tested only against fixtures written
by the same possibly-wrong understanding of the layout is
self-confirming. Two facts trigger the criterion:

1. The current MS-ONESTORE revision could not be pinned from
   the sources available during research (one of its nine
   could-not-verify items). Building to an unpinned spec
   revision means the layout constants themselves are
   unverified.
2. No independent .one writer exists in this environment to
   produce fixtures whose conformance does not depend on the
   parser author's reading.

What ships instead: format identification only. Files whose
header carries the .one Header GUID
{7B5C52E4-D88C-4DA7-AEB1-5378D02996D3} are identified as
"onenote" so they are counted and routed honestly, with no
structural claims made about their contents.

What would revive Tier 1/Tier 2: a pinned MS-ONESTORE
revision read end to end, plus either a real .one file with
known provenance or an independent writer, so fixtures can
disagree with the parser. Until both exist, an inventory
would be theatre, and this project does not ship theatre.
