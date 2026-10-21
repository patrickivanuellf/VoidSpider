# Perbandingan pada korpus pengembangan (eval/corpus, n=35)

| Alat | Cakupan kategori | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| laba-laba-pemindai | secrets, jwt, webshell, taint, iac | 21 | 0 | 0 | 14 | 100.0% | 100.0% | 100.0% | 0.0% |
| gitleaks | secrets, jwt | 7 | 1 | 1 | 4 | 87.5% | 87.5% | 87.5% | 20.0% |
| semgrep | taint, webshell, iac | 9 | 0 | 4 | 9 | 100.0% | 69.2% | 81.8% | 0.0% |
