#!/bin/bash
#
# Copyright (C) 2024 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Extracts the blocklist from Chromium source code and creates
# blocklist_{commit_id}.txt

if [[ -z ${CHROMIUM_SRC} ]]; then
  echo "\$CHROMIUM_SRC is not set"
  exit 1
fi

cert_verify_proc_blocklist_inc=${CHROMIUM_SRC}/net/cert/cert_verify_proc_blocklist.inc

# Extract the PEM and key file names from cert_verify_proc_blocklist.inc,
# excluding entries that are contained in kKnownInterceptionList.
function expandSPKIBlockList() {
  declare -a kSPKIBlockList
  declare -a kKnownInterceptionList
  inkKnownInterceptionList=false
  while read line; do
    if [[ "$line" =~ kKnownInterceptionList ]]; then
      inkKnownInterceptionList=true
    fi
    pem_or_key_file=$(echo "$line" | grep -E -o "[0-9a-f]*\.(pem|key)")
    if [[ "${pem_or_key_file}" ]]; then
      if [[ "${inkKnownInterceptionList}" == true ]]; then
        kKnownInterceptionList+=("${pem_or_key_file}")
      else
        kSPKIBlockList+=("${pem_or_key_file}")
      fi
    fi
  done < "${cert_verify_proc_blocklist_inc}"
  for f in ${kSPKIBlockList[@]}; do
    to_exclude=false
    for fint in ${kKnownInterceptionList[@]}; do
      if [[ "$f" = "$fint" ]]; then
        to_exclude=true
        break
      fi
    done
    if [[ "$to_exclude" == false ]]; then
      echo "$f"
    fi
  done
}

function create_blocklist() {
  expandSPKIBlockList | while read pem_or_key_file; do
    pem_or_key_path="${CHROMIUM_SRC}"/net/data/ssl/blocklist/"${pem_or_key_file}"
    if [[ ! -r "${pem_or_key_path}" ]]; then
      echo "Unknown file "${pem_or_key_path}""
      exit 1
    fi
    if [[ "${pem_or_key_path}" =~ .pem$ ]]; then
      openssl x509 -in ${pem_or_key_path} -pubkey -noout | openssl pkey -pubin -outform DER | sha1sum
    else
      openssl pkey -in ${pem_or_key_path} -pubin -outform DER | sha1sum
    fi
  done
}

commit_hash=$(git -C "$CHROMIUM_SRC"/net/data/ssl/blocklist/ log -1 --pretty=format:'%h' .)
blocklist_name=blocklist_${commit_hash}.txt
echo "Creating ${blocklist_name}"
create_blocklist | sort -u | cut -f 1 -d " " > "${blocklist_name}"
