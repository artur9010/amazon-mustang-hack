#!/system/bin/sh
# Post-root cleanup, executed by the exploit (full init_cred caps).
# Round 4 (final): com.amazon.venezia is already persisted-disabled
# (package-restrictions.xml / packages.xml enabled="3"). Just wipe the stale
# data dirs; the disabled package will not recreate them.
exec >/data/local/tmp/rootcmd.log 2>&1
set -x

echo "=== rootcmd start uid=$(id -u) caps=$(grep CapEff /proc/self/status) ==="

for p in $(pgrep -f com.amazon.venezia 2>/dev/null); do kill -9 "$p" 2>/dev/null; done

rm -rf /data/data/com.amazon.venezia
rm -rf /data/user/0/com.amazon.venezia
rm -rf /data/user_de/0/com.amazon.venezia
rm -rf /data/media/0/.imagecache/com.amazon.venezia
rm -rf /data/media/0/Android/data/com.amazon.venezia
rm -rf /data/securedStorageLocation/com.amazon.venezia
rm -rf /data/data/com.amazon.firelauncher/files/lib_icons/*venezia*
rm -rf /data/system/package_cache/*/*venezia*
rm -rf /data/misc/profiles/*/*venezia*

echo "=== remaining references ==="
find /data -maxdepth 4 -iname '*venezia*' 2>/dev/null
echo "=== pm disabled ==="
pm list packages -d 2>/dev/null | grep -i venezia
sync
echo "=== rootcmd end ==="
