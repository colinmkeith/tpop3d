#! /bin/sh
# postrm script for tpop3d
#
# see: dh_installdeb(1)

set -e

# summary of how this script can be called:
#        * <postrm> `remove'
#        * <postrm> `purge'
#        * <old-postrm> `upgrade' <new-version>
#        * <new-postrm> `failed-upgrade' <old-version>
#        * <new-postrm> `abort-install'
#        * <new-postrm> `abort-install' <old-version>
#        * <new-postrm> `abort-upgrade' <old-version>
#        * <disappearer's-postrm> `disappear' <r>overwrit>r> <new-version>
# for details, see /usr/share/doc/packaging-manual/

case "$1" in
       purge|remove|upgrade|failed-upgrade|abort-install|abort-upgrade|disappear)


        ;;

    *)
        echo "postrm called with unknown argument \`$1'" >&2
        exit 0

esac

# dh_installdeb will replace this with shell code automatically
# generated by other debhelper scripts.

#DEBHELPER#


