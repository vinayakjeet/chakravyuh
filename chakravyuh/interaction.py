"""Defense interaction: which pairs earn their place.

For a pair (a, b): reduction(config) is the ASR drop relative to no defense.
Synergy = reduction(a+b) - reduction(a) - reduction(b). Positive means the
pair removes more together than either removes alone, summed: super-additive.
Negative means the second layer mostly repeats work the first already did:
redundant. Published layering data shows strong diminishing returns past three
or four layers; this table is where that shows up or does not on this corpus.
"""

from __future__ import annotations

from dataclasses import dataclass

from chakravyuh.defenses import SINGLE_DEFENSES, config_name
from chakravyuh.scoring import asr_by_config
from chakravyuh.types import RunResult


@dataclass(frozen=True)
class PairVerdict:
    pair: str
    asr_a: float
    asr_b: float
    asr_pair: float
    reduction_a: float
    reduction_b: float
    reduction_pair: float
    synergy: float
    verdict: str


def classify(results: list[RunResult]) -> list[PairVerdict]:
    asr = asr_by_config(results)
    baseline_key = config_name(())
    if baseline_key not in asr:
        return []
    base = asr[baseline_key]

    out = []
    for i, a in enumerate(SINGLE_DEFENSES):
        for b in SINGLE_DEFENSES[i + 1:]:
            name_a, name_b, name_pair = a, b, config_name((a, b))
            if name_pair not in asr:
                continue
            red_a = base - asr[name_a]
            red_b = base - asr[name_b]
            red_pair = base - asr[name_pair]
            synergy = red_pair - red_a - red_b
            if synergy > 0.01:
                verdict = "super-additive"
            elif synergy < -0.01:
                verdict = "redundant"
            else:
                verdict = "additive"
            out.append(PairVerdict(
                pair=f"{a} + {b}",
                asr_a=asr[name_a],
                asr_b=asr[name_b],
                asr_pair=asr[name_pair],
                reduction_a=red_a,
                reduction_b=red_b,
                reduction_pair=red_pair,
                synergy=synergy,
                verdict=verdict,
            ))
    return out
