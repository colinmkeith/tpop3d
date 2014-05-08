tpop3d
======

Clone of tpop3d from http://savannah.nongnu.org/git/?group=tpop3d

Added support for authenticating against a CDB backend.

We chose this at Hagen Software, because CDB's are optimized for reading and updates are atomic.
This is ideal for mail authentication because you only ever read user/pass/spool data, and this
means that reads can be made from a local DB instead of each POP3 connection setting up a MySQL
connection and dealing with network or MySQL server latencies or a remote server being down.

Add to this the atomic updates, meaning that we can marshal changes behind the scenes and
apply them at once and we have a winner. Clients update their POP3 passwords only rarely,
so we have an infrequently read-only database. It sounds ideal for CDB's.
