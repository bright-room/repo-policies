package main

import rego.v1

# --- typescript: pnpm 以外を禁止(層1 OSV の前提 = pnpm-lock.yaml を守る) ---

deny contains msg if {
	input.package_json != null
	pm := object.get(input.package_json, "packageManager", "")
	not pnpm_pinned(pm)
	msg := "package.json: packageManager は pnpm@<version> 固定(corepack で pnpm を強制する)"
}

# packageManager は未設定(null)や pnpm 以外を deny 対象にする。
# object.get の default はキー欠落時のみ効くため、値が null の場合に startswith が
# 型エラーを起こす。is_string ガードで null を安全に非適合として扱う。
pnpm_pinned(pm) if {
	is_string(pm)
	startswith(pm, "pnpm@")
}

deny contains msg if {
	input.package_json != null
	some f in ["yarn.lock", "package-lock.json", "npm-shrinkwrap.json"]
	input.exists[f]
	msg := sprintf("%s を置かない(pnpm 専用リポ。kotlin-js-store/yarn.lock は対象外)", [f])
}

# --- kotlin (KMP): kotlin-js-store/yarn.lock は必ずコミット(OSV の検査対象にする) ---

deny contains msg if {
	input.exists["kotlin-js-store"]
	not input.kotlin_js_store_yarn_lock_tracked
	msg := "kotlin-js-store/yarn.lock を git 管理下に置く(.gitignore から外す)"
}

# --- python: lockfile 必須(OSV の検査対象にする) ---

deny contains msg if {
	input.exists["pyproject.toml"]
	not input.exists["uv.lock"]
	not input.exists["poetry.lock"]
	msg := "python プロジェクトは uv.lock か poetry.lock をコミットする"
}

# --- terraform: .terraform.lock.hcl 必須 ---

deny contains msg if {
	input.terraform.has_tf
	not input.terraform.has_lock
	msg := ".terraform.lock.hcl をコミットする(provider のピン留め)"
}

# --- jvm (gradle): lockfile 必須 — endpoint-gate / mindstock への lockfile 導入完了後に有効化する
#     (spec 2026-07-14 §7。有効化 = 下のコメントを外すだけ)
# deny contains msg if {
# 	input.gradle.has_settings
# 	not input.gradle.has_lockfile
# 	msg := "Gradle dependency locking を有効にして gradle.lockfile をコミットする"
# }
