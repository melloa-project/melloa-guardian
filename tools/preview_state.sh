#!/usr/bin/env bash
set -euo pipefail
umask 077

action="${1:-}"
requested_target="${2:-}"
guardian_binary="${3:-}"
marker_name=".melloa-guardian-preview"
marker_value_prefix="disposable public Guardian preview handoff v1"
marker_value=""
control=""
control_identity=""
created_target=false
target_identity=""

directory_identity() {
  local path="$1"
  if stat -Lc '%d:%i' -- "$path" >/dev/null 2>&1; then
    stat -Lc '%d:%i' -- "$path"
  else
    stat -Lf '%d:%i' "$path"
  fi
}

if [[ -z "$action" || -z "$requested_target" ]]; then
  echo "usage: preview_state.sh <create|clean> <handoff-directory> [guardianctl]" >&2
  exit 2
fi
if [[ "$action" != "create" && "$action" != "clean" ]]; then
  echo "unknown preview handoff action: $action" >&2
  exit 2
fi

target_name="$(basename -- "$requested_target")"
if [[ "$target_name" == "." || "$target_name" == ".." || "$target_name" == "/" ]]; then
  echo "refusing unsafe Guardian preview handoff path: $requested_target" >&2
  exit 2
fi

target_parent="$(dirname -- "$requested_target")"
if [[ "$action" == "create" ]]; then
  mkdir -p -- "$target_parent"
elif [[ ! -d "$target_parent" ]]; then
  echo "Guardian preview handoff does not exist: $requested_target"
  exit 0
fi
target_parent="$(cd "$target_parent" && pwd -P)"
target="$target_parent/$target_name"
if [[ "$target_parent" == "/" || "$target" == "/" ]]; then
  echo "refusing unsafe Guardian preview handoff path: $target" >&2
  exit 2
fi

create_handoff() {
  if [[ -e "$target" || -L "$target" ]]; then
    echo "refusing to overwrite Guardian preview handoff: $target" >&2
    exit 2
  fi
  if [[ ! -x "$guardian_binary" ]]; then
    echo "guardianctl is not executable: $guardian_binary" >&2
    exit 2
  fi
  guardian_binary="$(cd -P -- "$(dirname -- "$guardian_binary")" && pwd -P)/$(basename -- "$guardian_binary")"

  remove_control_directory() {
    local observed_identity=""
    if [[ -z "$control" ]]; then
      return 0
    fi
    if [[ -z "$control_identity" || -L "$control" || ! -d "$control" ]]; then
      echo "refusing changed Guardian preview control path: $control" >&2
      return 1
    fi
    if ! observed_identity="$(directory_identity "$control")"; then
      echo "cannot verify Guardian preview control path: $control" >&2
      return 1
    fi
    if [[ "$observed_identity" != "$control_identity" ]]; then
      echo "refusing changed Guardian preview control path: $control" >&2
      return 1
    fi
    if ! rmdir -- "$control"; then
      echo "refusing non-empty Guardian preview control path: $control" >&2
      return 1
    fi
  }

  remove_created_target() {
    local observed_identity=""
    if [[ "$created_target" != true ]]; then
      return 0
    fi
    if [[ ! -e "$target" && ! -L "$target" ]]; then
      return 0
    fi
    if [[ -z "$target_identity" || -L "$target" || ! -d "$target" ]]; then
      echo "refusing changed Guardian preview handoff during rollback: $target" >&2
      return 1
    fi
    if ! observed_identity="$(directory_identity "$target")"; then
      echo "cannot verify Guardian preview handoff during rollback: $target" >&2
      return 1
    fi
    if [[ "$observed_identity" != "$target_identity" ]]; then
      echo "refusing changed Guardian preview handoff during rollback: $target" >&2
      return 1
    fi
    if ! (
      cd -P -- "$target" || exit 1
      if [[ "$(directory_identity .)" != "$target_identity" \
        || "$(directory_identity "$target")" != "$target_identity" ]]; then
        exit 1
      fi
      shopt -s dotglob nullglob
      local entries=(*)
      shopt -u dotglob nullglob
      local entry
      for entry in "${entries[@]}"; do
        case "$entry" in
          "$marker_name"|status.json|public.pem) ;;
          *) exit 1 ;;
        esac
      done
      rm -f -- "$marker_name" status.json public.pem
    ); then
      echo "refusing changed Guardian preview handoff during rollback: $target" >&2
      return 1
    fi
    if [[ -L "$target" || ! -d "$target" ]]; then
      echo "refusing changed Guardian preview handoff during rollback: $target" >&2
      return 1
    fi
    if ! observed_identity="$(directory_identity "$target")" \
      || [[ "$observed_identity" != "$target_identity" ]] \
      || ! rmdir -- "$target"; then
      echo "refusing changed Guardian preview handoff during rollback: $target" >&2
      return 1
    fi
  }

  cleanup_create() {
    local result=$?
    local cleanup_result=0
    trap - EXIT
    if ! remove_control_directory; then
      cleanup_result=2
    fi
    if ! remove_created_target; then
      cleanup_result=2
    fi
    if [[ "$result" -eq 0 && "$cleanup_result" -ne 0 ]]; then
      result="$cleanup_result"
    fi
    exit "$result"
  }

  local canonical_control=""
  local initial_control_identity=""
  control="$(mktemp -d "${TMPDIR:-/tmp}/melloa-guardian-control.XXXXXX")"
  if ! initial_control_identity="$(directory_identity "$control")"; then
    rmdir -- "$control"
    echo "cannot identify Guardian preview control directory" >&2
    return 2
  fi
  control_identity="$initial_control_identity"
  trap cleanup_create EXIT
  if [[ -L "$control" || ! -d "$control" ]] \
    || ! canonical_control="$(cd -P -- "$control" && pwd -P)"; then
    echo "Guardian preview control path changed during creation: $control" >&2
    return 2
  fi
  control="$canonical_control"
  if [[ -L "$control" || ! -d "$control" \
    || "$(directory_identity "$control")" != "$control_identity" ]]; then
    echo "Guardian preview control path changed during creation: $control" >&2
    return 2
  fi

  mkdir -m 0700 -- "$target"
  created_target=true
  target_identity="$(directory_identity "$target")"

  (
    cd -P -- "$control"
    local bound_identity=""
    local path_identity=""
    if ! bound_identity="$(directory_identity .)" \
      || [[ -L "$control" || ! -d "$control" ]] \
      || ! path_identity="$(directory_identity "$control")" \
      || [[ "$bound_identity" != "$control_identity" \
        || "$path_identity" != "$control_identity" ]]; then
      echo "Guardian preview control path changed before use: $control" >&2
      exit 2
    fi

    cleanup_control_contents() {
      local result=$?
      local cleanup_result=0
      local observed_identity=""
      trap - EXIT
      if ! observed_identity="$(directory_identity .)"; then
        echo "cannot verify bound Guardian preview control directory" >&2
        cleanup_result=2
      elif [[ "$observed_identity" != "$control_identity" ]]; then
        echo "refusing changed bound Guardian preview control directory" >&2
        cleanup_result=2
      else
        # Never dereference $control here: the verified CWD keeps the original
        # directory inode bound even if its path is replaced while Guardian runs.
        shopt -s nullglob
        local temporary=(.guardian-*)
        shopt -u nullglob
        if ! rm -f -- \
          status.json audit.jsonl private.pem public.pem guardian.lock \
          "${temporary[@]}"; then
          echo "failed to remove bound Guardian preview control material" >&2
          cleanup_result=2
        fi
      fi
      if [[ "$result" -eq 0 && "$cleanup_result" -ne 0 ]]; then
        result="$cleanup_result"
      fi
      exit "$result"
    }
    trap cleanup_control_contents EXIT

    local guardian_flags=(
      --status-file status.json
      --audit-file audit.jsonl
      --private-key-file private.pem
      --public-key-file public.pem
      --lock-file guardian.lock
    )
    "$guardian_binary" init \
      --instance-id local-preview-guardian \
      --key-id guardian.status-v1 \
      "${guardian_flags[@]}"
    "$guardian_binary" transition \
      --mode offline \
      --reason owner.local_preview \
      "${guardian_flags[@]}"

    exec 8<status.json
    exec 9<public.pem
    marker_value="$marker_value_prefix $target_identity"
    (
      cd -P -- "$target"
      local status_created=false
      local public_key_created=false
      local marker_created=false
      cleanup_publication() {
        local result=$?
        local cleanup_result=0
        local observed_identity=""
        trap - EXIT
        if [[ "$result" -ne 0 ]]; then
          if ! observed_identity="$(directory_identity .)"; then
            echo "cannot verify bound Guardian preview handoff during rollback" >&2
            cleanup_result=2
          elif [[ "$observed_identity" != "$target_identity" ]]; then
            echo "refusing changed bound Guardian preview handoff during rollback" >&2
            cleanup_result=2
          else
            local created=()
            [[ "$status_created" == true ]] && created+=(status.json)
            [[ "$public_key_created" == true ]] && created+=(public.pem)
            [[ "$marker_created" == true ]] && created+=("$marker_name")
            if [[ "${#created[@]}" -gt 0 ]] && ! rm -f -- "${created[@]}"; then
              echo "failed to roll back Guardian preview handoff publication" >&2
              cleanup_result=2
            fi
          fi
        fi
        if [[ "$result" -eq 0 && "$cleanup_result" -ne 0 ]]; then
          result="$cleanup_result"
        fi
        exit "$result"
      }
      trap cleanup_publication EXIT
      if [[ "$(pwd -P)" != "$target" \
        || "$(directory_identity .)" != "$target_identity" \
        || "$(directory_identity "$target")" != "$target_identity" ]]; then
        echo "Guardian preview handoff path changed during creation: $target" >&2
        exit 2
      fi
      set -o noclobber
      exec 3>status.json
      status_created=true
      cat <&8 >&3
      exec 3>&-
      chmod 0444 status.json
      exec 3>public.pem
      public_key_created=true
      cat <&9 >&3
      exec 3>&-
      chmod 0444 public.pem
      exec 3>"$marker_name"
      marker_created=true
      printf '%s\n' "$marker_value" >&3
      exec 3>&-
      chmod 0444 "$marker_name"
      if [[ "$(pwd -P)" != "$target" \
        || "$(directory_identity .)" != "$target_identity" \
        || "$(directory_identity "$target")" != "$target_identity" ]]; then
        echo "Guardian preview handoff path changed during publication: $target" >&2
        exit 2
      fi
      trap - EXIT
    )
  )

  remove_control_directory
  control=""
  control_identity=""
  created_target=false
  trap - EXIT

  echo
  echo "Public Guardian preview handoff ready; temporary signing material was removed."
  printf 'export GUARDIAN_STATUS=%q\n' "$target/status.json"
  printf 'export GUARDIAN_PUBLIC_KEY=%q\n' "$target/public.pem"
  echo "Next: from the Melloa checkout, run \`make preview\`."
}

clean_handoff() {
  if [[ ! -e "$target" && ! -L "$target" ]]; then
    echo "Guardian preview handoff is already absent: $target"
    return
  fi
  if [[ -L "$target" || ! -d "$target" ]]; then
    echo "refusing to clean an invalid Guardian preview handoff: $target" >&2
    exit 2
  fi

  local cleanup_identity
  cleanup_identity="$(directory_identity "$target")"
  marker_value="$marker_value_prefix $cleanup_identity"
  (
    cd -P -- "$target"
    if [[ "$(pwd -P)" != "$target" \
      || "$(directory_identity .)" != "$cleanup_identity" \
      || "$(directory_identity "$target")" != "$cleanup_identity" ]]; then
      echo "refusing Guardian preview handoff path changed during cleanup: $target" >&2
      exit 2
    fi
    if [[ -L "$marker_name" || ! -f "$marker_name" || "$(<"$marker_name")" != "$marker_value" ]]; then
      echo "refusing to clean an unmarked Guardian preview handoff: $target" >&2
      exit 2
    fi
    if [[ -L status.json || ! -f status.json || -L public.pem || ! -f public.pem ]]; then
      echo "refusing to clean a malformed Guardian preview handoff: $target" >&2
      exit 2
    fi

    shopt -s dotglob nullglob
    local entries=(*)
    shopt -u dotglob nullglob
    if [[ "${#entries[@]}" -ne 3 ]]; then
      echo "refusing to clean Guardian preview handoff with unexpected files: $target" >&2
      exit 2
    fi

    chmod 0700 .
    if [[ "$(directory_identity .)" != "$cleanup_identity" \
      || "$(directory_identity "$target")" != "$cleanup_identity" ]]; then
      echo "refusing Guardian preview handoff path changed before cleanup: $target" >&2
      exit 2
    fi
    rm -- "$marker_name" status.json public.pem
  )
  if [[ -L "$target" || ! -d "$target" \
    || "$(directory_identity "$target")" != "$cleanup_identity" ]]; then
    echo "Guardian preview handoff path changed before final directory removal: $target" >&2
    exit 2
  fi
  if ! rmdir -- "$target"; then
    echo "Guardian preview handoff path changed before final directory removal: $target" >&2
    exit 2
  fi
  echo "Guardian preview handoff removed: $target"
}

case "$action" in
  create) create_handoff ;;
  clean) clean_handoff ;;
esac
