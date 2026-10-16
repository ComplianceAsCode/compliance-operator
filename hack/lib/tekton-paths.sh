# Functions for hack/resolve-konflux-images.sh: read the paths a Konflux pipeline
# watches from .tekton, and tell whether a change touches them, the way Konflux
# decides whether to build.
#
# Konflux (Pipelines as Code) runs a pipeline when its
# pipelinesascode.tekton.dev/on-cel-expression annotation is true. Each path it
# watches is a "<pattern>".pathChanged() call, and Pipelines as Code matches the
# pattern with github.com/gobwas/glob compiled without separators, so * also
# matches / (pkg/matcher/cel.go). For patterns made of literal characters, *
# and ?, bash's [[ $file == $pattern ]] matches exactly the same files.
#
# The functions fail rather than guess. They print why and return 2 when a
# trigger isn't <other conditions> && ( "<pattern>".pathChanged() || ... ), when
# a pattern uses glob syntax other than * and ?, or when git fails, so that an
# error can't be mistaken for "no match" (return 1). Run them from the
# repository root. They expect $repo, the Quay repository the components push
# to, as in the script.

# tekton_pipeline <component> <pull-request|push>: the pipeline in .tekton that
# builds the component, found by its output image rather than by its file name.
# That also works on release branches, where for example
# compliance-operator-release-1-10-push.yaml pushes to compliance-operator-release.
tekton_pipeline() {
  local image files
  # shellcheck disable=SC2154 # $repo is set by the script.
  case $2 in
    pull-request) image="$repo/$1:on-pr-{{revision}}" ;;
    push) image="$repo/$1:{{revision}}" ;;
    *) echo "tekton_pipeline: unknown pipeline kind: $2" >&2; return 2 ;;
  esac
  files=$(awk -v want="$image" '
    {
      line = $0
      sub(/\r$/, "", line); sub(/^[[:space:]]+/, "", line); sub(/[[:space:]]+$/, "", line)
      if (line !~ /^value:[[:space:]]/) next
      v = line; sub(/^value:[[:space:]]+/, "", v)
      if (v ~ /^".*"$/ || v ~ /^\047.*\047$/) v = substr(v, 2, length(v) - 2)
      if (v == want) { print FILENAME; nextfile }
    }' .tekton/*-"$2".yaml 2>/dev/null) || true
  if [[ -z $files ]]; then
    echo "No pipeline in .tekton/*-$2.yaml builds $image" >&2
    return 2
  fi
  if [[ $files == *$'\n'* ]]; then
    echo "More than one pipeline in .tekton builds $image: ${files//$'\n'/, }" >&2
    return 2
  fi
  printf '%s\n' "$files"
}

# tekton_cel <pipeline>: the pipeline's on-cel-expression, with YAML's line
# folding and quoting undone. It reads plain, single-quoted, double-quoted and
# block (| or >) values, on one line or several.
tekton_cel() {
  local cel status=0 rest
  cel=$(awk '
    BEGIN { key = "pipelinesascode.tekton.dev/on-cel-expression:"; state = 0 }
    {
      sub(/\r$/, "")
      line = $0; sub(/^[[:space:]]+/, "", line)
      if (index(line, key) == 1) {
        if (state != 0) { dup = 1; exit }
        state = 1; indent = match($0, /[^[:space:]]/)
        v = substr(line, length(key) + 1); sub(/^[[:space:]]+/, "", v)
        if (v ~ /^[|>][-+0-9]*[[:space:]]*$/) v = ""
        out = v; next
      }
      if (state == 1) {
        if (line == "") next
        if (match($0, /[^[:space:]]/) <= indent) { state = 2; next }
        out = (out == "" ? line : out " " line)
      }
    }
    END { if (dup) exit 3; if (state == 0) exit 4; print out }' "$1") || status=$?
  case $status in
    0) ;;
    3) echo "$1 has more than one on-cel-expression" >&2; return 2 ;;
    4) echo "$1 has no on-cel-expression" >&2; return 2 ;;
    *) echo "Could not read $1" >&2; return 2 ;;
  esac
  case $cel in
    \'*)
      if [[ ${#cel} -lt 2 || $cel != *\' ]]; then
        echo "$1: its on-cel-expression has an unterminated quote" >&2
        return 2
      fi
      cel=${cel:1:${#cel}-2}
      cel=${cel//\'\'/\'}
      ;;
    \"*)
      if [[ ${#cel} -lt 2 || $cel != *\" ]]; then
        echo "$1: its on-cel-expression has an unterminated quote" >&2
        return 2
      fi
      cel=${cel:1:${#cel}-2}
      # A CEL expression only needs \" in a double-quoted YAML value. Refuse
      # any other escape rather than decode it wrong.
      rest=${cel//\\\"/}
      if [[ $rest == *\\* ]]; then
        echo "$1: its on-cel-expression uses YAML escapes other than \\\"" >&2
        return 2
      fi
      cel=${cel//\\\"/\"}
      ;;
  esac
  printf '%s\n' "$cel"
}

# tekton_patterns <pipeline>: the path patterns its trigger watches, one per
# line.
tekton_patterns() {
  local cel n_calls lits n_lits skel before after middle between p
  local tok=$'\x1f' call_re="[rR]?(\"[^\"\\\\]*\"|'[^'\\\\]*')\\.pathChanged\\(\\)"
  cel=$(tekton_cel "$1") || return 2
  if [[ $cel == *"$tok"* || $cel == *'#'* || $cel == *files.* ]]; then
    echo "$1: its on-cel-expression uses '#' or files.*, which this script can't read" >&2
    return 2
  fi
  n_calls=$({ grep -oF '.pathChanged()' <<<"$cel" || true; } | wc -l)
  if (( n_calls == 0 )); then
    echo "$1 watches no paths: its on-cel-expression has no pathChanged() calls" >&2
    return 2
  fi
  lits=$(grep -oE "$call_re" <<<"$cel" || true)
  n_lits=$(grep -c . <<<"$lits" || true)
  if (( n_lits != n_calls )); then
    echo "$1: could read only $n_lits of its $n_calls pathChanged() calls" >&2
    return 2
  fi
  # Konflux builds when the other conditions hold and any pattern matches only
  # if the calls form one group joined by ||, and the group is joined to the
  # rest of the expression by &&. Check that with each call replaced by $tok.
  skel=$(sed -E "s/$call_re/$tok/g" <<<"$cel")
  before=${skel%%"$tok"*}
  after=${skel##*"$tok"}
  middle=${skel#"$before"}
  middle=${middle%"$after"}
  between=${middle//"$tok"/}
  between=${between//||/}
  between=${between//[()[:space:]]/}
  if [[ -n $between ]] ||
     ! [[ $before =~ (^|\&\&)[\(\)[:space:]]*$ ]] ||
     ! [[ $after =~ ^[\(\)[:space:]]*($|\&\&) ]]; then
    echo "$1: its pathChanged() calls aren't one group joined by || and ANDed with the other conditions" >&2
    return 2
  fi
  while IFS= read -r p; do
    p=${p%.pathChanged()}
    p=${p#[rR]}
    p=${p:1:${#p}-2}
    if [[ -z $p || $p == *[][{}\\]* ]]; then
      echo "$1: pattern '$p' uses glob syntax other than * and ?, which this script can't match like Konflux" >&2
      return 2
    fi
    printf '%s\n' "$p"
  done <<<"$lits"
}

# path_matches <file> <pattern>...: print the first pattern the file matches, or
# return 1 if it matches none. Only use patterns from tekton_patterns.
path_matches() {
  local file=$1 pattern
  shift
  for pattern; do
    # shellcheck disable=SC2053 # $pattern is a glob on purpose.
    if [[ $file == $pattern ]]; then
      printf '%s\n' "$pattern"
      return 0
    fi
  done
  return 1
}

# changed_match <base> <head> <pattern>...: whether the change a PR makes, from
# the merge base of <base> and <head> to <head> (the files GitHub shows, and
# Konflux matches), touches a file that matches a pattern. Prints
# "<file> (<pattern>)" for the first one; returns 1 if none does.
changed_match() {
  local base=$1 head=$2 list file pattern found
  shift 2
  if ! git merge-base "$base" "$head" >/dev/null 2>&1; then
    echo "The checkout lacks $base, $head or their merge base" >&2
    return 2
  fi
  list=$(mktemp) || return 2
  if ! git -c core.quotePath=false diff --name-only --no-renames -z "$base...$head" >"$list"; then
    rm -f "$list"
    echo "git diff $base...$head failed" >&2
    return 2
  fi
  found=
  while IFS= read -r -d '' file; do
    if pattern=$(path_matches "$file" "$@"); then
      found="$file ($pattern)"
      break
    fi
  done <"$list"
  rm -f "$list"
  [[ -n $found ]] || return 1
  printf '%s\n' "$found"
}

# last_matching_commit <commit> <pattern>...: the newest commit in <commit>'s
# first-parent history whose own change, against its first parent, touches a
# file that matches a pattern. That's the commit whose Konflux push build is the
# image <commit> has. Returns 1 if no commit among the newest 500 does.
last_matching_commit() {
  local tip=$1 commits list commit parent file found=
  shift
  if ! git rev-parse -q --verify "$tip^{commit}" >/dev/null; then
    echo "The checkout lacks commit $tip" >&2
    return 2
  fi
  if ! commits=$(git rev-list --first-parent --max-count=500 "$tip"); then
    echo "git rev-list $tip failed" >&2
    return 2
  fi
  list=$(mktemp) || return 2
  while IFS= read -r commit; do
    parent=$(git rev-parse -q --verify "$commit^1") || break
    if ! git -c core.quotePath=false diff --name-only --no-renames -z "$parent" "$commit" >"$list"; then
      rm -f "$list"
      echo "git diff $parent $commit failed" >&2
      return 2
    fi
    while IFS= read -r -d '' file; do
      if path_matches "$file" "$@" >/dev/null; then
        found=$commit
        break 2
      fi
    done <"$list"
  done <<<"$commits"
  rm -f "$list"
  [[ -n $found ]] || return 1
  printf '%s\n' "$found"
}

# strict_tag <component> <base> [<head>]: the tag of the component's Konflux
# build that a job testing <base>, or PR <head> against <base>, must use:
# on-pr-<head> when the PR changes the component's sources, else the full SHA
# of the newest base commit that does, whose push build has the image <base>
# has. It says on stderr why. Returns 2 on errors, including no such commit
# among the newest 500. It only decides which build: the caller checks that
# Quay has it, and waits for it.
strict_tag() {
  local component=$1 base=$2 head=${3:-} pipeline list hit commit status
  local -a patterns
  if [[ -n $head ]]; then
    pipeline=$(tekton_pipeline "$component" pull-request) || return 2
    # Capture first: mapfile < <(...) would hide a failure as an empty list.
    list=$(tekton_patterns "$pipeline") || return 2
    mapfile -t patterns <<<"$list"
    status=0
    hit=$(changed_match "$base" "$head" "${patterns[@]}") || status=$?
    case $status in
      0)
        echo "This PR changes $hit, so it's tested with its own build of $component" >&2
        printf '%s\n' "on-pr-$head"
        return 0
        ;;
      1) ;;
      *) return 2 ;;
    esac
  fi
  pipeline=$(tekton_pipeline "$component" push) || return 2
  list=$(tekton_patterns "$pipeline") || return 2
  mapfile -t patterns <<<"$list"
  status=0
  commit=$(last_matching_commit "$base" "${patterns[@]}") || status=$?
  case $status in
    0) ;;
    1)
      echo "None of the newest 500 commits of $base changes $component's sources" >&2
      return 2
      ;;
    *) return 2 ;;
  esac
  echo "Testing with the build of $commit, the newest commit of $base that changes $component's sources" >&2
  printf '%s\n' "$commit"
}
