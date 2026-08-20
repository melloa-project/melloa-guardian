#!/usr/bin/env bash
set -euo pipefail

guardian_binary="${1:?guardianctl path required}"
preview_script="${2:?preview state script path required}"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/melloa-guardian-preview-test.XXXXXX")"
handoff="$test_root/handoff"
external="$test_root/external"
copied="$test_root/copied"
failed_handoff="$test_root/failed-handoff"
failing_binary="$test_root/failing-guardianctl"
replacing_binary="$test_root/replacing-guardianctl"
attack_moved="$test_root/displaced-control"
attack_replacement="$test_root/replacement-control"
attack_path_file="$test_root/control-path"
attack_log="$test_root/control-attack.log"
attack_control=""

cleanup() {
  set +e
  if [[ -n "$attack_control" && -L "$attack_control" ]]; then
    unlink "$attack_control"
  elif [[ -n "$attack_control" && -d "$attack_control" ]]; then
    rm -f -- "$attack_control/status.json"
    rmdir "$attack_control" 2>/dev/null
  fi
  if [[ -d "$attack_moved" ]]; then
    rm -f -- \
      "$attack_moved/status.json" \
      "$attack_moved/audit.jsonl" \
      "$attack_moved/private.pem" \
      "$attack_moved/public.pem" \
      "$attack_moved/guardian.lock" \
      "$attack_moved"/.guardian-*
    rmdir "$attack_moved" 2>/dev/null
  fi
  if [[ -d "$attack_replacement" ]]; then
    rm -f -- "$attack_replacement/status.json"
    rmdir "$attack_replacement" 2>/dev/null
  fi
  if [[ -L "$handoff" ]]; then
    unlink "$handoff"
  elif [[ -d "$handoff" ]]; then
    rm -f -- "$handoff/unexpected"
    bash "$preview_script" clean "$handoff" >/dev/null 2>&1
  fi
  if [[ -d "$external" ]]; then
    bash "$preview_script" clean "$external" >/dev/null 2>&1
  fi
  if [[ -d "$copied" ]]; then
    rm -f -- \
      "$copied/.melloa-guardian-preview" \
      "$copied/status.json" \
      "$copied/public.pem"
    rmdir "$copied" 2>/dev/null
  fi
  if [[ -d "$failed_handoff" ]]; then
    rm -f -- \
      "$failed_handoff/.melloa-guardian-preview" \
      "$failed_handoff/status.json" \
      "$failed_handoff/public.pem"
    rmdir "$failed_handoff" 2>/dev/null
  fi
  rm -f -- \
    "$failing_binary" \
    "$replacing_binary" \
    "$attack_path_file" \
    "$attack_log"
  rmdir -- "$test_root" 2>/dev/null
}
trap cleanup EXIT

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'printf secret >private.pem' \
  'printf temporary >.guardian-private-leak' \
  'exit 1' >"$failing_binary"
chmod 0700 "$failing_binary"
if TMPDIR="$test_root" bash "$preview_script" \
  create "$failed_handoff" "$failing_binary" >/dev/null 2>&1; then
  echo "preview handoff creation accepted a failed Guardian command" >&2
  exit 1
fi
test ! -e "$failed_handoff"
if compgen -G "$test_root/melloa-guardian-control.*" >/dev/null; then
  echo "failed preview handoff creation leaked temporary control state" >&2
  exit 1
fi
rm -- "$failing_binary"

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'original="$PWD"' \
  'printf "%s\n" "$original" >"$CONTROL_ATTACK_PATH_FILE"' \
  'mv -- "$original" "$CONTROL_ATTACK_MOVED"' \
  'case "$CONTROL_ATTACK_KIND" in' \
  '  directory)' \
  '    mkdir -- "$original"' \
  '    printf keep >"$original/status.json"' \
  '    ;;' \
  '  symlink)' \
  '    ln -s -- "$CONTROL_ATTACK_REPLACEMENT" "$original"' \
  '    ;;' \
  '  *) exit 99 ;;' \
  'esac' \
  'printf secret >private.pem' \
  'printf temporary >.guardian-private-leak' \
  'exit 1' >"$replacing_binary"
chmod 0700 "$replacing_binary"

exercise_control_replacement() {
  local attack_kind="$1"
  printf keep >"$attack_replacement/status.json"
  if CONTROL_ATTACK_KIND="$attack_kind" \
    CONTROL_ATTACK_MOVED="$attack_moved" \
    CONTROL_ATTACK_REPLACEMENT="$attack_replacement" \
    CONTROL_ATTACK_PATH_FILE="$attack_path_file" \
    TMPDIR="$test_root" \
    bash "$preview_script" create "$failed_handoff" "$replacing_binary" \
      >/dev/null 2>"$attack_log"; then
    echo "preview handoff creation accepted a replaced control path" >&2
    exit 1
  fi
  attack_control="$(<"$attack_path_file")"
  grep -q "refusing changed Guardian preview control path" "$attack_log"
  test ! -e "$failed_handoff"
  test -d "$attack_moved"
  test ! -e "$attack_moved/private.pem"
  if compgen -G "$attack_moved/.guardian-*" >/dev/null; then
    echo "control replacement left Guardian temporary material behind" >&2
    exit 1
  fi
  test -f "$attack_replacement/status.json"
  test "$(<"$attack_replacement/status.json")" = keep
  if [[ "$attack_kind" == directory ]]; then
    test -d "$attack_control"
    test -f "$attack_control/status.json"
    test "$(<"$attack_control/status.json")" = keep
    rm -- "$attack_control/status.json"
    rmdir -- "$attack_control"
  else
    test -L "$attack_control"
    unlink "$attack_control"
  fi
  attack_control=""
  rmdir -- "$attack_moved"
  rm -- "$attack_replacement/status.json"
  rmdir -- "$attack_replacement"
  rm -- "$attack_path_file" "$attack_log"
  if compgen -G "$test_root/melloa-guardian-control.*" >/dev/null; then
    echo "control replacement test leaked a temporary control path" >&2
    exit 1
  fi
}

mkdir "$attack_replacement"
exercise_control_replacement directory
mkdir "$attack_replacement"
exercise_control_replacement symlink
rm -- "$replacing_binary"

TMPDIR="$test_root" bash "$preview_script" create "$handoff" "$guardian_binary" >/dev/null
test -f "$handoff/.melloa-guardian-preview"
test -f "$handoff/status.json"
test -f "$handoff/public.pem"
test ! -e "$handoff/private.pem"
test ! -e "$handoff/audit.jsonl"
test ! -e "$handoff/guardian.lock"
if compgen -G "$test_root/melloa-guardian-control.*" >/dev/null; then
  echo "preview handoff creation leaked temporary control state" >&2
  exit 1
fi

TMPDIR="$test_root" bash "$preview_script" create "$external" "$guardian_binary" >/dev/null
mkdir "$copied"
cp -p \
  "$handoff/.melloa-guardian-preview" \
  "$handoff/status.json" \
  "$handoff/public.pem" \
  "$copied/"
if bash "$preview_script" clean "$copied" >/dev/null 2>&1; then
  echo "preview handoff cleanup accepted a marker copied to another inode" >&2
  exit 1
fi
test -f "$copied/status.json"
rm -- \
  "$copied/.melloa-guardian-preview" \
  "$copied/status.json" \
  "$copied/public.pem"
rmdir "$copied"

if bash "$preview_script" create "$handoff" "$guardian_binary" >/dev/null 2>&1; then
  echo "preview handoff creation overwrote existing state" >&2
  exit 1
fi

touch "$handoff/unexpected"
if bash "$preview_script" clean "$handoff" >/dev/null 2>&1; then
  echo "preview handoff cleanup removed a directory with unexpected files" >&2
  exit 1
fi
test -f "$handoff/status.json"
rm -- "$handoff/unexpected"

bash "$preview_script" clean "$handoff" >/dev/null
test ! -e "$handoff"

ln -s "$external" "$handoff"
if bash "$preview_script" clean "$handoff" >/dev/null 2>&1; then
  echo "preview handoff cleanup followed a directory symlink" >&2
  exit 1
fi
test -f "$external/status.json"
unlink "$handoff"
bash "$preview_script" clean "$external" >/dev/null

mkdir "$handoff"
if bash "$preview_script" clean "$handoff" >/dev/null 2>&1; then
  echo "preview handoff cleanup removed an unmarked directory" >&2
  exit 1
fi
rmdir "$handoff"

trap - EXIT
rmdir "$test_root"
