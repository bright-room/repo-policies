#!/usr/bin/env bash
# 検査対象リポの「事実」を JSON で出力する。ポリシー判定は一切しない(判定は Rego 側)。
# 使い方: collect-facts.sh <target-repo-root>
#
# ガードレール: 事実は必ず「リポ root 直下の固定パス」「git index」(git ls-files /
# --error-unmatch / check-ignore)「git index から導出した固定パス」から取ること。
# 再帰的なファイル探索を足すと、呼び出し元 workflow が workspace 直下に checkout する
# .repo-policies/(untracked)を誤って拾う。
set -euo pipefail
cd "${1:?usage: collect-facts.sh <target-repo-root>}"

exists() { [ -e "$1" ] && echo true || echo false; }
tracked() { git ls-files --error-unmatch "$1" >/dev/null 2>&1 && echo true || echo false; }
# .gitignore にマッチするか。ファイルが存在しなくても判定できる(CI の fresh checkout では
# ignore されたファイルはそもそも存在しないため、存在ベースの検知では拾えない)。
ignored() { git check-ignore -q "$1" 2>/dev/null && echo true || echo false; }
# git 管理下のファイル一覧を JSON 配列で。vendor/ 配下(依存のコピー)のマニフェストは除外
list_tracked() { git ls-files "$@" | { grep -vE '(^|/)vendor/' || true; } | jq -R . | jq -s .; }

# *.tf の存在(.terraform/ 配下のキャッシュは除外)
tf_files=$(git ls-files '*.tf' | grep -v '/\.terraform/' | head -1 || true)
# .terraform.lock.hcl がどこかに 1 つでも git 管理下にあるか
tf_lock=$(git ls-files '*.terraform.lock.hcl' '.terraform.lock.hcl' | head -1 || true)
# settings.gradle(.kts) の存在
gradle_settings=$(git ls-files 'settings.gradle' 'settings.gradle.kts' '**/settings.gradle' '**/settings.gradle.kts' | head -1 || true)
# gradle.lockfile がどこかにあるか
gradle_lock=$(git ls-files '*gradle.lockfile' | head -1 || true)

package_json="null"
if [ -f package.json ]; then
  package_json=$(jq '{packageManager: (.packageManager // null)}' package.json)
fi

# kotlin-js-store の事実。gradle root(settings.gradle のあるディレクトリ。repo root は常に
# 候補)ごとに kotlin-js-store の場所を導出し、js target / wasmJs target 両方の lockfile
# パスを検査する(js は kotlin-js-store/yarn.lock、wasmJs は kotlin-js-store/wasm/yarn.lock)。
kjs_facts() {
  {
    echo ""
    git ls-files 'settings.gradle' 'settings.gradle.kts' '**/settings.gradle' '**/settings.gradle.kts' |
      sed -E 's|[^/]*$||'
  } | sort -u | while IFS= read -r dir; do
    store="${dir}kotlin-js-store"
    jq -n --arg k "$store" --argjson exists "$(exists "$store")" \
      '{type: "dir", key: $k, value: {exists: $exists}}'
    for p in "$store/yarn.lock" "$store/wasm/yarn.lock"; do
      jq -n --arg k "$p" \
        --argjson exists "$(exists "$p")" \
        --argjson tracked "$(tracked "$p")" \
        --argjson ignored "$(ignored "$p")" \
        '{type: "lock", key: $k, value: {exists: $exists, tracked: $tracked, ignored: $ignored}}'
    done
  done | jq -s '{
    dirs:  (map(select(.type == "dir"))  | from_entries),
    locks: (map(select(.type == "lock")) | from_entries)
  }'
}

# workflow と composite action の uses: を全件列挙(pinned 判定は Rego 側)
actions_uses() {
  git ls-files '.github/workflows/*.yml' '.github/workflows/*.yaml' \
    'action.yml' 'action.yaml' '**/action.yml' '**/action.yaml' |
    while IFS= read -r f; do
      { grep -E '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]' "$f" || true; } |
        sed -E 's/\r$//; s/^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*//; s/[[:space:]]+#.*$//; s/^["'\'']//; s/["'\'']$//; s/[[:space:]]*$//' |
        jq -R --arg file "$f" '{file: $file, uses: .}'
    done | jq -s .
}

jq -n \
  --argjson package_json "$package_json" \
  --argjson yarn_lock "$(exists yarn.lock)" \
  --argjson package_lock "$(exists package-lock.json)" \
  --argjson shrinkwrap "$(exists npm-shrinkwrap.json)" \
  --argjson kjs "$(kjs_facts)" \
  --argjson pyprojects "$(list_tracked 'pyproject.toml' '**/pyproject.toml')" \
  --argjson py_locks "$(list_tracked 'uv.lock' '**/uv.lock' 'poetry.lock' '**/poetry.lock')" \
  --argjson has_tf "$([ -n "$tf_files" ] && echo true || echo false)" \
  --argjson has_tf_lock "$([ -n "$tf_lock" ] && echo true || echo false)" \
  --argjson has_gradle "$([ -n "$gradle_settings" ] && echo true || echo false)" \
  --argjson has_gradle_lock "$([ -n "$gradle_lock" ] && echo true || echo false)" \
  --argjson actions_uses "$(actions_uses)" \
  --argjson go_mods "$(list_tracked 'go.mod' '**/go.mod')" \
  --argjson go_sums "$(list_tracked 'go.sum' '**/go.sum')" \
  --argjson cargo_tomls "$(list_tracked 'Cargo.toml' '**/Cargo.toml')" \
  --argjson cargo_locks "$(list_tracked 'Cargo.lock' '**/Cargo.lock')" \
  '{
    package_json: $package_json,
    exists: {
      "yarn.lock": $yarn_lock,
      "package-lock.json": $package_lock,
      "npm-shrinkwrap.json": $shrinkwrap
    },
    kotlin_js_store: $kjs,
    python: { pyprojects: $pyprojects, locks: $py_locks },
    terraform: { has_tf: $has_tf, has_lock: $has_tf_lock },
    gradle: { has_settings: $has_gradle, has_lockfile: $has_gradle_lock },
    github_actions: { uses: $actions_uses },
    go: { mod_files: $go_mods, sum_files: $go_sums },
    rust: { cargo_tomls: $cargo_tomls, cargo_locks: $cargo_locks }
  }'
