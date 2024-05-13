# Updating the blocklist based on Chromium's source code

```shell
$ cd chromium/src/net/data/ssl/blocklist

# Get the latest commit hash in this directory.
$ COMMIT_HASH=`git log -1 --pretty=format:'%h' .`

# Extract the hash of the public keys.
$ ((for f in *.pem; do openssl x509 -in $f -pubkey -noout | openssl pkey -pubin -outform DER | sha1sum; done) && \
   (for f in *.key; do openssl pkey -in $f -pubin -outform DER | sha1sum; done)) \
  | sort -u | cut -f 1 -d " " > blocklist_${COMMIT_HASH}.txt
```
