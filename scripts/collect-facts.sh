#!/usr/bin/env bash
# 検査対象リポの「事実」を JSON で出力する。ポリシー判定は一切しない(判定は Rego 側)。
# 使い方: collect-facts.sh <target-repo-root>
#
# ガードレール: 事実は必ず「リポ root 直下の固定パス」か「git index」(git ls-files /
# --error-unmatch)から取ること。再帰的なファイル探索を足すと、呼び出し元 workflow が
# workspace 直下に checkout する .repo-policies/(untracked)を誤って拾う。
set -euo pipefail
cd "${1:?usage: collect-facts.sh <target-repo-root>}"

exists() { [ -e "$1" ] && echo true || echo false; }
tracked() { git ls-files --error-unmatch "$1" >/dev/null 2>&1 && echo true || echo false; }

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

jq -n \
  --argjson package_json "$package_json" \
  --argjson yarn_lock "$(exists yarn.lock)" \
  --argjson package_lock "$(exists package-lock.json)" \
  --argjson shrinkwrap "$(exists npm-shrinkwrap.json)" \
  --argjson pyproject "$(exists pyproject.toml)" \
  --argjson uv_lock "$(exists uv.lock)" \
  --argjson poetry_lock "$(exists poetry.lock)" \
  --argjson kjs_dir "$(exists kotlin-js-store)" \
  --argjson kjs_lock_tracked "$(tracked kotlin-js-store/yarn.lock)" \
  --argjson has_tf "$([ -n "$tf_files" ] && echo true || echo false)" \
  --argjson has_tf_lock "$([ -n "$tf_lock" ] && echo true || echo false)" \
  --argjson has_gradle "$([ -n "$gradle_settings" ] && echo true || echo false)" \
  --argjson has_gradle_lock "$([ -n "$gradle_lock" ] && echo true || echo false)" \
  '{
    package_json: $package_json,
    exists: {
      "yarn.lock": $yarn_lock,
      "package-lock.json": $package_lock,
      "npm-shrinkwrap.json": $shrinkwrap,
      "pyproject.toml": $pyproject,
      "uv.lock": $uv_lock,
      "poetry.lock": $poetry_lock,
      "kotlin-js-store": $kjs_dir
    },
    kotlin_js_store_yarn_lock_tracked: $kjs_lock_tracked,
    terraform: { has_tf: $has_tf, has_lock: $has_tf_lock },
    gradle: { has_settings: $has_gradle, has_lockfile: $has_gradle_lock }
  }'
