# repo-policies

bright-room / kukv の管理リポジトリが満たすべきセキュリティ前提を conftest (OPA/Rego) で検査するポリシー集。
各リポに fanout が配布する `.github/workflows/security.yml` の `policy` ジョブから **main 参照**で実行される
(ルール変更はこのリポの merge だけで全リポに反映される。だからこそ main への変更は CI green が必須)。

## 構成

- `policy/repo.rego` — deny ルール(facts に応じて言語別ルールが条件発火)
- `policy/repo_test.rego` — conftest verify で回るユニットテスト
- `scripts/collect-facts.sh` — 検査対象リポから事実(ファイル存在・git 管理状態・package.json 抜粋)を JSON 化

## ルール追加の手順

1. `scripts/collect-facts.sh` に必要な事実を足す(判定は入れない)
2. `policy/repo.rego` に deny ルールを足す
3. `policy/repo_test.rego` に正例・反例を足す
4. PR → CI(conftest verify)green → merge。fanout 側の変更は不要
