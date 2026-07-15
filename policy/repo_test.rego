package main

import rego.v1

no_lock := {"exists": false, "tracked": false, "ignored": false}

tracked_lock := {"exists": true, "tracked": true, "ignored": false}

clean_kjs := {
	"dirs": {"kotlin-js-store": {"exists": false}},
	"locks": {
		"kotlin-js-store/yarn.lock": no_lock,
		"kotlin-js-store/wasm/yarn.lock": no_lock,
	},
}

clean_facts := {
	"package_json": null,
	"exists": {"yarn.lock": false, "package-lock.json": false, "npm-shrinkwrap.json": false},
	"kotlin_js_store": clean_kjs,
	"python": {"pyprojects": [], "locks": []},
	"terraform": {"has_tf": false, "has_lock": false},
	"gradle": {"has_settings": false, "has_lockfile": false},
	"github_actions": {"uses": []},
	"go": {"mod_files": [], "sum_files": []},
	"rust": {"cargo_tomls": [], "cargo_locks": []},
}

test_clean_repo_has_no_denies if {
	count(deny) == 0 with input as clean_facts
}

test_pnpm_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"package_json": {"packageManager": "pnpm@10.12.0"}})
}

test_non_pnpm_denied if {
	msgs := deny with input as object.union(clean_facts, {"package_json": {"packageManager": "npm@11.0.0"}})
	some msg in msgs
	contains(msg, "packageManager")
}

test_missing_package_manager_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"package_json": {"packageManager": null}})
}

test_foreign_lockfile_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {
		"package_json": {"packageManager": "pnpm@10.12.0"},
		"exists": object.union(clean_facts.exists, {"yarn.lock": true}),
	})
}

# --- kotlin (KMP) ---

test_kmp_js_lock_tracked_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"kotlin_js_store": {
		"dirs": {"kotlin-js-store": {"exists": true}},
		"locks": object.union(clean_kjs.locks, {"kotlin-js-store/yarn.lock": tracked_lock}),
	}})
}

# wasmJs target は kotlin-js-store/wasm/yarn.lock を使う。それだけが tracked でも適合
test_kmp_wasm_only_lock_tracked_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"kotlin_js_store": {
		"dirs": {"kotlin-js-store": {"exists": true}},
		"locks": object.union(clean_kjs.locks, {"kotlin-js-store/wasm/yarn.lock": tracked_lock}),
	}})
}

test_kmp_js_and_wasm_locks_tracked_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"kotlin_js_store": {
		"dirs": {"kotlin-js-store": {"exists": true}},
		"locks": {
			"kotlin-js-store/yarn.lock": tracked_lock,
			"kotlin-js-store/wasm/yarn.lock": tracked_lock,
		},
	}})
}

# fresh checkout では ignore されたファイルは存在しない。ignored の事実だけで検知できること
test_kmp_lock_gitignored_denied if {
	msgs := deny with input as object.union(clean_facts, {"kotlin_js_store": {
		"dirs": {"kotlin-js-store": {"exists": false}},
		"locks": object.union(clean_kjs.locks, {"kotlin-js-store/yarn.lock": {"exists": false, "tracked": false, "ignored": true}}),
	}})
	some msg in msgs
	contains(msg, ".gitignore から外して")
}

test_kmp_wasm_lock_gitignored_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"kotlin_js_store": {
		"dirs": {"kotlin-js-store": {"exists": true}},
		"locks": {
			"kotlin-js-store/yarn.lock": tracked_lock,
			"kotlin-js-store/wasm/yarn.lock": {"exists": false, "tracked": false, "ignored": true},
		},
	}})
}

# ローカル実行向け: 生成済みなのに未コミット
test_kmp_lock_exists_untracked_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"kotlin_js_store": {
		"dirs": {"kotlin-js-store": {"exists": true}},
		"locks": object.union(clean_kjs.locks, {"kotlin-js-store/yarn.lock": {"exists": true, "tracked": false, "ignored": false}}),
	}})
}

test_kmp_dir_without_tracked_lock_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"kotlin_js_store": object.union(clean_kjs, {"dirs": {"kotlin-js-store": {"exists": true}}})})
}

# ネストした gradle root(monorepo の app/ など)にも対応すること
test_kmp_nested_gradle_root_lock_tracked_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"kotlin_js_store": {
		"dirs": {"kotlin-js-store": {"exists": false}, "app/kotlin-js-store": {"exists": true}},
		"locks": object.union(clean_kjs.locks, {"app/kotlin-js-store/yarn.lock": tracked_lock}),
	}})
}

test_kmp_nested_gradle_root_lock_gitignored_denied if {
	msgs := deny with input as object.union(clean_facts, {"kotlin_js_store": {
		"dirs": {"kotlin-js-store": {"exists": false}, "app/kotlin-js-store": {"exists": false}},
		"locks": object.union(clean_kjs.locks, {"app/kotlin-js-store/yarn.lock": {"exists": false, "tracked": false, "ignored": true}}),
	}})
	some msg in msgs
	contains(msg, "app/kotlin-js-store/yarn.lock")
}

# jvm / native のみ: kotlin-js-store が生成されないので発火しない(clean_facts と同値)

# --- python ---

test_python_without_lock_denied if {
	msgs := deny with input as object.union(clean_facts, {"python": {"pyprojects": ["pyproject.toml"], "locks": []}})
	some msg in msgs
	contains(msg, "uv.lock か poetry.lock")
}

test_python_with_uv_lock_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"python": {"pyprojects": ["pyproject.toml"], "locks": ["uv.lock"]}})
}

test_python_with_poetry_lock_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"python": {"pyprojects": ["pyproject.toml"], "locks": ["poetry.lock"]}})
}

# uv workspace: メンバーの pyproject.toml は root の uv.lock に集約される
test_python_workspace_member_covered_by_root_lock_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"python": {"pyprojects": ["pyproject.toml", "packages/a/pyproject.toml"], "locks": ["uv.lock"]}})
}

test_python_nested_without_lock_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"python": {"pyprojects": ["services/api/pyproject.toml"], "locks": []}})
}

# 兄弟ディレクトリの lockfile では適合にならないこと
test_python_sibling_lock_not_covering_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"python": {"pyprojects": ["services/api/pyproject.toml"], "locks": ["services/web/uv.lock"]}})
}

# --- terraform ---

test_terraform_without_lock_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"terraform": {"has_tf": true, "has_lock": false}})
}

test_terraform_with_lock_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"terraform": {"has_tf": true, "has_lock": true}})
}

# --- github actions(workflow / composite action 共通の deny ルール) ---

test_gha_sha_pinned_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"github_actions": {"uses": [{"file": ".github/workflows/ci.yml", "uses": "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"}]}})
}

test_gha_tag_denied if {
	msgs := deny with input as object.union(clean_facts, {"github_actions": {"uses": [{"file": ".github/workflows/ci.yml", "uses": "actions/checkout@v4"}]}})
	some msg in msgs
	contains(msg, "commit SHA でピン留め")
}

test_gha_branch_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"github_actions": {"uses": [{"file": ".github/workflows/ci.yml", "uses": "actions/checkout@main"}]}})
}

test_gha_no_ref_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"github_actions": {"uses": [{"file": ".github/workflows/ci.yml", "uses": "actions/checkout"}]}})
}

test_gha_composite_action_tag_denied if {
	msgs := deny with input as object.union(clean_facts, {"github_actions": {"uses": [{"file": ".github/actions/setup/action.yml", "uses": "actions/setup-node@v5"}]}})
	some msg in msgs
	contains(msg, ".github/actions/setup/action.yml")
}

test_gha_local_action_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"github_actions": {"uses": [{"file": ".github/workflows/ci.yml", "uses": "./.github/actions/setup"}]}})
}

test_gha_reusable_workflow_sha_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"github_actions": {"uses": [{"file": ".github/workflows/ci.yml", "uses": "org/repo/.github/workflows/reuse.yml@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"}]}})
}

test_gha_docker_digest_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"github_actions": {"uses": [{"file": ".github/workflows/ci.yml", "uses": "docker://alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b"}]}})
}

test_gha_docker_tag_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"github_actions": {"uses": [{"file": ".github/workflows/ci.yml", "uses": "docker://alpine:3.20"}]}})
}

# --- go ---

test_go_with_sum_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"go": {"mod_files": ["go.mod"], "sum_files": ["go.sum"]}})
}

test_go_without_sum_denied if {
	msgs := deny with input as object.union(clean_facts, {"go": {"mod_files": ["go.mod"], "sum_files": []}})
	some msg in msgs
	contains(msg, "go.sum")
}

test_go_nested_without_sum_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"go": {"mod_files": ["go.mod", "tools/go.mod"], "sum_files": ["go.sum"]}})
}

test_go_nested_with_sum_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"go": {"mod_files": ["go.mod", "tools/go.mod"], "sum_files": ["go.sum", "tools/go.sum"]}})
}

# --- rust ---

test_rust_with_lock_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"rust": {"cargo_tomls": ["Cargo.toml"], "cargo_locks": ["Cargo.lock"]}})
}

test_rust_without_lock_denied if {
	msgs := deny with input as object.union(clean_facts, {"rust": {"cargo_tomls": ["Cargo.toml"], "cargo_locks": []}})
	some msg in msgs
	contains(msg, "Cargo.lock")
}

# tauri: src-tauri/ 配下に Cargo.toml と Cargo.lock が両方あるパターン
test_rust_tauri_nested_lock_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"rust": {"cargo_tomls": ["src-tauri/Cargo.toml"], "cargo_locks": ["src-tauri/Cargo.lock"]}})
}

# workspace: メンバーの Cargo.toml は root の Cargo.lock に集約される
test_rust_workspace_member_covered_by_root_lock_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"rust": {"cargo_tomls": ["Cargo.toml", "crates/foo/Cargo.toml"], "cargo_locks": ["Cargo.lock"]}})
}

test_rust_nested_without_any_lock_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"rust": {"cargo_tomls": ["src-tauri/Cargo.toml"], "cargo_locks": []}})
}
