Process Utilities
=================

This package contains a few utilities for Linux which use the `/proc`
filesystem to get and set information about processes.

* `plimit` gets or sets resource limits of a process

* `pfiles` lists the available file descriptors of a process and
  various attributes of each file descriptor

These utilities with a similar (or the same) interface exist on
Solaris and therefore can help sysadmins who miss them feel more
at home on Linux systems.


Installation
------------

It is best to create an RPM and install that:

    make dist
    rpmbuild -tb putils-<VERSION>.tar.bz2
    sudo dnf localinstall /path/to/putils-<VERSION>-RELEASE>.<ARCH>.rpm
