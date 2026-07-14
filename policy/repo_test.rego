package main

import rego.v1

clean_facts := {
	"package_json": null,
	"exists": {
		"yarn.lock": false, "package-lock.json": false, "npm-shrinkwrap.json": false,
		"pyproject.toml": false, "uv.lock": false, "poetry.lock": false,
		"kotlin-js-store": false
	},
	"kotlin_js_store_yarn_lock_tracked": false,
	"terraform": {"has_tf": false, "has_lock": false},
	"gradle": {"has_settings": false, "has_lockfile": false}
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

test_kmp_yarn_lock_ignored_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"exists": object.union(clean_facts.exists, {"kotlin-js-store": true})})
}

test_kmp_yarn_lock_tracked_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {
		"exists": object.union(clean_facts.exists, {"kotlin-js-store": true}),
		"kotlin_js_store_yarn_lock_tracked": true,
	})
}

test_python_without_lock_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"exists": object.union(clean_facts.exists, {"pyproject.toml": true})})
}

test_python_with_uv_lock_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"exists": object.union(clean_facts.exists, {"pyproject.toml": true, "uv.lock": true})})
}

test_terraform_without_lock_denied if {
	count(deny) > 0 with input as object.union(clean_facts, {"terraform": {"has_tf": true, "has_lock": false}})
}

test_terraform_with_lock_ok if {
	count(deny) == 0 with input as object.union(clean_facts, {"terraform": {"has_tf": true, "has_lock": true}})
}
