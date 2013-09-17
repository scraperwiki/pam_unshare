pam_unshare.so -- A pam module for creating mount namespaces
------------------------------------------------------------

Original code came from here

http://sourceforge.net/p/pam/patches/71/

Customized for scraperwiki to enable only unsharing for
users in a specific group.

Usage:

Put this wherever it needs to go in /etc/pam.d/*`:

```
session require pam_unshare.so <groupname>
```

