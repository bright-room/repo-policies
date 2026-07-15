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
	msg := sprintf("%s を置かない(pnpm 専用リポ。kotlin-js-store/ 配下の yarn.lock は対象外)", [f])
}

# --- kotlin (KMP): kotlin-js-store 配下の yarn.lock は必ずコミット(OSV の検査対象にする) ---
# 検査対象パスは gradle root(settings.gradle のあるディレクトリ + repo root)から導出される
# ためネストした gradle プロジェクトにも対応。js target は <root>/kotlin-js-store/yarn.lock、
# wasmJs target は <root>/kotlin-js-store/wasm/yarn.lock を使う。
# jvm / native のみのプロジェクトはディレクトリも lockfile も生成されないため、どのルールも発火しない。
# CI は fresh checkout(ignore されたファイルは存在しない)なので、存在チェックだけでは
# 「.gitignore で隠された lockfile」を検知できない。ignored の事実(git check-ignore)で直接検査する。

deny contains msg if {
	some path, lock in input.kotlin_js_store.locks
	lock.ignored
	not lock.tracked
	msg := sprintf("%s を .gitignore から外して git 管理下に置く", [path])
}

# ローカル実行(fresh checkout でない)向け: 生成済みなのに未コミットの lockfile を検知する
deny contains msg if {
	some path, lock in input.kotlin_js_store.locks
	lock.exists
	not lock.tracked
	msg := sprintf("%s を git 管理下に置く", [path])
}

deny contains msg if {
	some dir, info in input.kotlin_js_store.dirs
	info.exists
	not kjs_lock_tracked_under(dir)
	msg := sprintf("%s 配下の yarn.lock を git 管理下に置く", [dir])
}

kjs_lock_tracked_under(dir) if {
	some path, lock in input.kotlin_js_store.locks
	startswith(path, dir)
	lock.tracked
}

# --- python: pyproject.toml ごとに lockfile 必須(OSV の検査対象にする) ---
# uv workspace ではメンバーの lockfile は root の uv.lock に集約されるため、
# 「同じディレクトリか祖先ディレクトリ」に lockfile があれば適合。

deny contains msg if {
	some py in input.python.pyprojects
	not python_lock_covers(py)
	msg := sprintf("%s: uv.lock か poetry.lock をコミットする(uv workspace は root の uv.lock でよい)", [py])
}

python_lock_covers(py) if {
	some lock in input.python.locks
	lock_dir := trim_suffix(trim_suffix(lock, "uv.lock"), "poetry.lock")
	startswith(trim_suffix(py, "pyproject.toml"), lock_dir)
}

# --- terraform: .terraform.lock.hcl 必須 ---

deny contains msg if {
	input.terraform.has_tf
	not input.terraform.has_lock
	msg := ".terraform.lock.hcl をコミットする(provider のピン留め)"
}

# --- github actions: uses は commit SHA でピン留め必須(タグ・ブランチの付け替え攻撃対策) ---
# 対象は .github/workflows/ 配下の workflow と、リポ内の composite action(action.yml / action.yaml)

deny contains msg if {
	some entry in input.github_actions.uses
	not pinned_uses(entry.uses)
	msg := sprintf("%s: uses を commit SHA でピン留めする(%s)", [entry.file, entry.uses])
}

# ローカルアクション(./)は ref を持たないので対象外
pinned_uses(u) if startswith(u, "./")

# owner/repo@<40桁 sha>(reusable workflow も同形式)
pinned_uses(u) if regex.match(`@[0-9a-f]{40}$`, u)

# docker:// はイメージ digest でのピン留め
pinned_uses(u) if {
	startswith(u, "docker://")
	contains(u, "@sha256:")
}

# --- go: go.mod と同じディレクトリに go.sum 必須(OSV の検査対象にする) ---

deny contains msg if {
	some mod in input.go.mod_files
	sum := sprintf("%sgo.sum", [trim_suffix(mod, "go.mod")])
	not sum in input.go.sum_files
	msg := sprintf("%s: 同じディレクトリに go.sum をコミットする", [mod])
}

# --- rust: Cargo.toml ごとに Cargo.lock 必須(OSV の検査対象にする) ---
# workspace ではメンバーの lockfile は root の Cargo.lock に集約されるため、
# 「同じディレクトリか祖先ディレクトリ」に Cargo.lock があれば適合(tauri の src-tauri/ も同様)。

deny contains msg if {
	some toml in input.rust.cargo_tomls
	not cargo_lock_covers(toml)
	msg := sprintf("%s: Cargo.lock をコミットする(workspace の場合は root の Cargo.lock)", [toml])
}

cargo_lock_covers(toml) if {
	some lock in input.rust.cargo_locks
	startswith(trim_suffix(toml, "Cargo.toml"), trim_suffix(lock, "Cargo.lock"))
}

# --- jvm (gradle): lockfile 必須 — endpoint-gate / mindstock への lockfile 導入完了後に有効化する
#     (spec 2026-07-14 §7。有効化 = 下のコメントを外すだけ)
# deny contains msg if {
# 	input.gradle.has_settings
# 	not input.gradle.has_lockfile
# 	msg := "Gradle dependency locking を有効にして gradle.lockfile をコミットする"
# }
