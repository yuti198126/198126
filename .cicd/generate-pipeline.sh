#!/bin/bash
set -eo pipefail
# environment
. ./.cicd/helpers/general.sh
export PLATFORMS_JSON_ARRAY='[]'
[[ -z "$ROUNDS" ]] && export ROUNDS='1'
DISABLE_CONCURRENCY=${DISABLE_CONCURRENCY:-false}
LINUX_CONCURRENCY='8'
MAC_CONCURRENCY='2'
LINUX_CONCURRENCY_GROUP='eos-scheduled-build'
MAC_CONCURRENCY_GROUP='eos-scheduled-build-mac'
BUILDKITE_BUILD_AGENT_QUEUE='automation-eks-eos-builder-fleet'
BUILDKITE_TEST_AGENT_QUEUE='automation-eks-eos-tester-fleet'

# Determine if it's a forked PR and make sure to add git fetch so we don't have to git clone the forked repo's url
if [[ $BUILDKITE_BRANCH =~ ^pull/[0-9]+/head: ]]; then
  PR_ID=$(echo $BUILDKITE_BRANCH | cut -d/ -f2)
  export GIT_FETCH="git fetch -v --prune origin refs/pull/$PR_ID/head &&"
fi
# Determine which dockerfiles/scripts to use for the pipeline.
if [[ $PINNED == false ]]; then
    export PLATFORM_TYPE="unpinned"
else
    export PLATFORM_TYPE="pinned"
fi
for FILE in $(ls $CICD_DIR/platforms/$PLATFORM_TYPE); do
    # skip mac or linux by not even creating the json block
    ( [[ $SKIP_MAC == true ]] && [[ $FILE =~ 'macos' ]] ) && continue
    ( [[ $SKIP_LINUX == true ]] && [[ ! $FILE =~ 'macos' ]] ) && continue
    # use pinned or unpinned, not both sets of platform files
    if [[ $PINNED == false ]]; then
        export SKIP_CONTRACT_BUILDER=${SKIP_CONTRACT_BUILDER:-true}
        export SKIP_PACKAGE_BUILDER=${SKIP_PACKAGE_BUILDER:-true}
    fi
    export FILE_NAME="$(echo $FILE | awk '{split($0,a,/\.(d|s)/); print a[1] }')"
    # macos-10.14
    # ubuntu-16.04
    # skip Mojave if it's anything but the post-merge build
    if [[ "$FILE_NAME" =~ 'macos-10.14' && "$SKIP_MACOS_10_14" != 'false' && "$RUN_ALL_TESTS" != 'true' && ( "$BUILDKITE_SOURCE" != 'webhook' || "$BUILDKITE_PULL_REQUEST" != 'false' || ! "$BUILDKITE_MESSAGE" =~ 'Merge pull request' ) ]]; then
        export SKIP_MACOS_10_14='true'
        continue
    fi
    export PLATFORM_NAME="$(echo $FILE_NAME | cut -d- -f1 | sed 's/os/OS/g')"
    # macOS
    # ubuntu
    export PLATFORM_NAME_UPCASE="$(echo $PLATFORM_NAME | tr a-z A-Z)"
    # MACOS
    # UBUNTU
    export VERSION_MAJOR="$(echo $FILE_NAME | cut -d- -f2 | cut -d. -f1)"
    # 10
    # 16
    [[ "$(echo $FILE_NAME | cut -d- -f2)" =~ '.' ]] && export VERSION_MINOR="_$(echo $FILE_NAME | cut -d- -f2 | cut -d. -f2)" || export VERSION_MINOR=''
    # _14
    # _04
    export VERSION_FULL="$(echo $FILE_NAME | cut -d- -f2)"
    # 10.14
    # 16.04
    OLDIFS=$IFS
    IFS='_'
    set $PLATFORM_NAME
    IFS=$OLDIFS
    export PLATFORM_NAME_FULL="$(capitalize $1)$( [[ ! -z $2 ]] && echo "_$(capitalize $2)" || true ) $VERSION_FULL"
    [[ $FILE_NAME =~ 'amazon' ]] && export ICON=':aws:'
    [[ $FILE_NAME =~ 'ubuntu' ]] && export ICON=':ubuntu:'
    [[ $FILE_NAME =~ 'centos' ]] && export ICON=':centos:'
    [[ $FILE_NAME =~ 'macos' ]] && export ICON=':darwin:'
    . $HELPERS_DIR/file-hash.sh $CICD_DIR/platforms/$PLATFORM_TYPE/$FILE # returns HASHED_IMAGE_TAG, etc
    # Anka Template and Tags
    export ANKA_TAG_BASE='clean::cicd::git-ssh::nas::brew::buildkite-agent'
    if [[ $FILE_NAME =~ 'macos-10.14' ]]; then
      export ANKA_TEMPLATE_NAME='10.14.6_6C_14G_40G'
    elif [[ $FILE_NAME =~ 'macos-10.15' ]]; then
      export ANKA_TEMPLATE_NAME='10.15.4_6C_14G_40G'
    else # Linux
      export ANKA_TAG_BASE=''
      export ANKA_TEMPLATE_NAME=''
    fi
    export PLATFORMS_JSON_ARRAY=$(echo $PLATFORMS_JSON_ARRAY | jq -c '. += [{ 
        "FILE_NAME": env.FILE_NAME, 
        "PLATFORM_NAME": env.PLATFORM_NAME,
        "PLATFORM_NAME_UPCASE": env.PLATFORM_NAME_UPCASE,
        "VERSION_MAJOR": env.VERSION_MAJOR,
        "VERSION_MINOR": env.VERSION_MINOR,
        "VERSION_FULL": env.VERSION_FULL,
        "PLATFORM_NAME_FULL": env.PLATFORM_NAME_FULL,
        "DOCKERHUB_FULL_TAG": env.FULL_TAG,
        "HASHED_IMAGE_TAG": env.HASHED_IMAGE_TAG,
        "ICON": env.ICON,
        "ANKA_TAG_BASE": env.ANKA_TAG_BASE,
        "ANKA_TEMPLATE_NAME": env.ANKA_TEMPLATE_NAME
        }]')
done
# set build_source whether triggered or not
if [[ ! -z ${BUILDKITE_TRIGGERED_FROM_BUILD_ID} ]]; then
    export BUILD_SOURCE="--build \$BUILDKITE_TRIGGERED_FROM_BUILD_ID"
fi
export BUILD_SOURCE=${BUILD_SOURCE:---build \$BUILDKITE_BUILD_ID}
# set trigger_job if master/release/develop branch and webhook
if [[ ! $BUILDKITE_PIPELINE_SLUG =~ 'lrt' ]] && [[ $BUILDKITE_BRANCH =~ ^release/[0-9]+\.[0-9]+\.x$ || $BUILDKITE_BRANCH =~ ^master$ || $BUILDKITE_BRANCH =~ ^develop$ || "$SKIP_LONG_RUNNING_TESTS" == 'false' ]]; then
    [[ $BUILDKITE_SOURCE != 'schedule' ]] && export TRIGGER_JOB=true
fi
# run LRTs synchronously when running full test suite
if [[ "$RUN_ALL_TESTS" == 'true' && "$SKIP_LONG_RUNNING_TESTS" != 'true' ]]; then
    export BUILD_SOURCE="--build \$BUILDKITE_BUILD_ID"
    export SKIP_LONG_RUNNING_TESTS='false'
    export TRIGGER_JOB='false'
fi
oIFS="$IFS"
IFS=$''
nIFS=$IFS # fix array splitting (\n won't work)
IFS=$oIFS
cat <<EOF
  - wait:
EOF
for ROUND in $(seq 1 $ROUNDS); do
    IFS=$''
    echo "    # round $ROUND of $ROUNDS"
cat <<EOF
  - label: ":darwin: macOS 10.15 - ship_test"
    command:
      - "git clone \$BUILDKITE_REPO eos && cd eos &&  git checkout -f \$BUILDKITE_COMMIT && git submodule update --init --recursive"
      - "cd eos && buildkite-agent artifact download build.tar.gz . --step ':darwin: macOS 10.15 - Build' --build '14c9ef65-59c3-4a9d-934f-f80dbcd9a184' && tar -xzf build.tar.gz"
      - "cd eos && ./.cicd/test.sh scripts/serial-test.sh ship_test"
    plugins:
      - EOSIO/anka#v0.6.0:
          no-volume: true
          inherit-environment-vars: true
          vm-name: 10.15.4_6C_14G_40G
          vm-registry-tag: clean::cicd::git-ssh::nas::brew::buildkite-agent::eos-macos-10.15-pinned-cbf68aff3c49d8c672b28157f2433a977a386c81
          always-pull: true
          debug: true
          wait-network: true
          failover-registries:
            - 'registry_1'
            - 'registry_2'
      - EOSIO/skip-checkout#v0.1.1:
          cd: ~
    agents: "queue=mac-anka-test-fleet"
    retry:
      manual:
        permit_on_passed: true
    timeout: 60
    skip: ${SKIP_MACOS_10_15}

  - label: ":darwin: macOS 10.15 - ship_test"
    command:
      - "git clone \$BUILDKITE_REPO eos && cd eos &&  git checkout -f \$BUILDKITE_COMMIT && git submodule update --init --recursive"
      - "cd eos && buildkite-agent artifact download build.tar.gz . --step ':darwin: macOS 10.15 - Build' --build '14c9ef65-59c3-4a9d-934f-f80dbcd9a184' && tar -xzf build.tar.gz"
      - "cd eos && ./.cicd/test.sh scripts/serial-test.sh ship_test"
    plugins:
      - EOSIO/anka#v0.6.0:
          no-volume: true
          inherit-environment-vars: true
          vm-name: 10.15.4_6C_14G_40G
          vm-registry-tag: clean::cicd::git-ssh::nas::brew::buildkite-agent::eos-macos-10.15-pinned-cbf68aff3c49d8c672b28157f2433a977a386c81
          always-pull: true
          debug: true
          wait-network: true
          failover-registries:
            - 'registry_1'
            - 'registry_2'
      - EOSIO/skip-checkout#v0.1.1:
          cd: ~
    agents: "queue=mac-anka-test-fleet"
    retry:
      manual:
        permit_on_passed: true
    timeout: 60
    skip: ${SKIP_MACOS_10_15}

EOF
    IFS=$oIFS
    if [[ "$ROUND" != "$ROUNDS" ]]; then
        echo '  - wait:'
        echo '    continue_on_failure: true'
        echo ''
    fi
done
IFS=$oIFS
