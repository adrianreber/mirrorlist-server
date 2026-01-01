mirrorlist-server
=================

The mirrorlist-server uses the data created by `MirrorManager2
<https://github.com/fedora-infra/mirrormanager2>`_ to answer client request for
the "best" mirror.

This implementation of the mirrorlist-server is written in Rust. The original
version of the mirrorlist-server was part of the MirrorManager2 repository and
it is implemented using Python. While moving from Python2 to Python3 one of
the problems was that the data exchange format (Python Pickle) did not support
running the MirrorManager2 backend with Python2 and the mirrorlist frontend
with Python3. To have a Pickle independent data exchange format protobuf was
introduced. The first try to use protobuf in the python mirrorlist
implementation required a lot more memory than the Pickle based implementation
(3.5GB instead of 1.1GB). That is one of the reasons a new mirrorlist-server
implementation was needed.

Another reason to rewrite the mirrorlist-server is its architecture. The
Python based version requires the Apache HTTP server or something that can
run the included wsgi. The wsgi talks over a socket to the actual
mirrorlist-server. In Fedora's MirrorManager2 instance this runs in a container
which runs behind HAProxy. This implementation in Rust directly uses a HTTP
library to reduce the number of involved components.

In addition to being simpler this implementation also requires less memory
than the Python version.

generate-mirrorlist-cache
=========================

Another re-implementation of a part of MirrorManager2. generate-mirrorlist-cache
talks to the MirrorManager2 database to create the input files for the previously
mentioned mirrorlist-server. generate-mirrorlist-cache is a drop in replacement
for the Python script mm2_refresh_mirrorlist_cache.

In Fedora's setup the Python version requires up to 50 minutes and 10GB of memory.
This Rust version is finished in under one minute and only requires 600MB.

Bundled Dependencies
--------------------

This project includes a vendored copy of the ``treebitmap`` library
(https://github.com/hroi/treebitmap) in ``src/treebitmap/``. The original
crate has been yanked from crates.io and the GitHub repository has been
archived, so the source code is included directly in this project.

The ``treebitmap`` library is licensed under the MIT license. See
``src/treebitmap/LICENSE-MIT`` for the full license text.

Building
--------

The project can be built using::

    $ cargo build

Usage
-----

The mirrorlist-server requires multiple input files which all can be created
using MirrorManager2 or generate-mirrorlist-cache.
