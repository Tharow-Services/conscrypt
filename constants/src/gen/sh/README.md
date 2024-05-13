# Updating the blocklist based on Chromium's source code

There are 2 scripts in this directory:
- extract\_SPKIBlockList.sh is executed by a conscrypt maintainer. It extracts
  the blocklist from a Chromium repository and stores the output in a file
  named blocklist\_{commit\_id}.txt
- generate\_blocklist.sh is executed by the build system automatically. It
  consumes the blocklist\_{commit\_id}.txt file and generates a static Java
  class, usable by conscrypt.

To execute extract\_SPKIBlockList:
```shell
$ CHROMIUM_SRC=~/chromium/src sh extract\_SPKIBlockList.sh
```
