#!/usr/bin/bash
set -eu

umask 077
export LC_ALL=C

if (( $# != 1 )); then
    exit 64
fi

if [[ ! -x /usr/bin/systemctl ]]; then
    printf 'UNAVAILABLE\tSYSTEMCTL_NOT_FOUND\n'
    exit 0
fi

properties='LoadState,ActiveState,SubState,UnitFileState,Type,MainPID,ExecMainStatus,Result,NRestarts,ActiveEnterTimestampMonotonic'

if output=$(/usr/bin/systemctl show --no-pager --property="$properties" -- "$1" 2>/dev/null); then
    printf '%s\n' "$output"
else
    printf 'ERROR\tSERVICE_QUERY_FAILED\n'
fi
