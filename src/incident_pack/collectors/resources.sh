#!/usr/bin/bash
set -eu

umask 077
export LC_ALL=C

if (($# != 0)); then
	exit 64
fi

if [[ -r /proc/loadavg ]]; then
	IFS=' ' read -r load_1m load_5m load_15m _ </proc/loadavg
	printf 'LOAD\t%s\t%s\t%s\n' "$load_1m" "$load_5m" "$load_15m"
else
	printf 'UNAVAILABLE\tLOADAVG_NOT_FOUND\n'
fi

if [[ -r /proc/meminfo ]]; then
	while IFS=' :' read -r key value unit _; do
		case "$key" in
		MemTotal | MemAvailable | SwapTotal | SwapFree)
			printf 'MEMORY\t%s\t%s\t%s\n' "$key" "$value" "$unit"
			;;
		esac
	done </proc/meminfo
else
	printf 'UNAVAILABLE\tMEMINFO_NOT_FOUND\n'
fi

for pressure_source in cpu memory io; do
	pressure_path="/proc/pressure/$pressure_source"
	if [[ -r "$pressure_path" ]]; then
		while IFS= read -r pressure_line; do
			printf 'PRESSURE\t%s\t%s\n' "$pressure_source" "$pressure_line"
		done <"$pressure_path"
	else
		printf 'UNAVAILABLE\tPRESSURE_%s_NOT_FOUND\n' "${pressure_source^^}"
	fi
done

if [[ ! -x /usr/bin/findmnt ]]; then
	printf 'UNAVAILABLE\tFINDMNT_NOT_FOUND\n'
elif filesystem=$(/usr/bin/findmnt --target / --bytes --noheadings --output FSTYPE,SIZE,USED,AVAIL,USE% 2>/dev/null); then
	read -r filesystem_type size_bytes used_bytes available_bytes used_percent _ <<<"$filesystem"
	printf 'FILESYSTEM\t/\t%s\t%s\t%s\t%s\t%s\n' \
		"$filesystem_type" "$size_bytes" "$used_bytes" "$available_bytes" "$used_percent"
else
	printf 'UNAVAILABLE\tFILESYSTEM_QUERY_FAILED\n'
fi
