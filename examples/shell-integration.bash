# Source this file in your HOST Bash. Export only explicitly selected aliases
# and functions, review the output, then pass it to `create --shell-rc FILE`.
# Usage: devsession_export ./review-me.bash alias:ll function:project_root
# Functions may embed secrets or depend on unavailable files: inspect the result.
devsession_export() {
    local output=$1 item
    shift
    ( umask 077
      : > "$output" || exit
      for item; do
          case $item in
              alias:*) alias "${item#alias:}" >> "$output" || exit ;;
              function:*) declare -f "${item#function:}" >> "$output" || exit ;;
              *) printf 'Expected alias:NAME or function:NAME\n' >&2; exit 2 ;;
          esac
      done
    )
}
