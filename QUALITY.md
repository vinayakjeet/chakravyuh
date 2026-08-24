# Quality Bar

What "done" means here. A capability ships only when it maps to one of these.

1. **Three columns or nothing.** Any published defense number carries benign
   utility, utility under attack, and attack success rate together.
2. **Every number regenerates.** If `uv run python scripts/status.py` does not
   print it, it does not go in the README or on the site.
3. **Variance is published.** Cells are means over at least 3 seeded
   repetitions with stdev attached.
4. **The victim is named and dated.** Model string and susceptibility-table
   date appear beside every table.
5. **Adaptive coverage.** Each defense layer has at least one transform aimed
   at its specific assumption, run against it by name.
6. **Cost is measured.** Token multiplier and inspect cost per layer sit next
   to effectiveness, never in a separate document.
7. **Negative results stay published.** Redundant layers and broken defenses
   are findings, not embarrassments to prune.
8. **Offline determinism.** Tests and benches run without network, credentials,
   or GPU; same seed, same numbers.
