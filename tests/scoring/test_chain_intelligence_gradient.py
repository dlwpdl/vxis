"""Phase 5: Chain Intelligence gradient — depth + count + crown bonus.

문제: _calc_chain_intelligence 는 step-function (0 → 50 → 100 → 150) 으로
max_chain_depth 만 평가. 단점:
  - chain_count 무시 → 여러 체인 구축해도 보상 없음
  - 체인 임팩트 무시 → 5-step recon-only 체인과 3-step RCE 체인이 같은 점수
  - 깊이 1-2 사이 gradient 없음 (둘 다 50)

해결: 연속 gradient 도입 (max 150 유지, 기존 kill-chain 최대값 불변).
  depth_points  = min(max_depth * 25, 125)          # 1,2,3,4,5+ → 25,50,75,100,125
  count_bonus   = min((chain_count - 1) * 10, 15)   # 2+ 체인 → +10, 3+ → +15
  crown_bonus   = 25 if any step.level >= 3 else 0  # critical 임팩트 도달
  score = min(depth_points + count_bonus + crown_bonus, 150)

이 gradient 는 기존 경계값 (5-step full kill chain = 150) 을 유지하면서
Brain 이 "더 많이, 더 깊게, 더 임팩트 있게" 체인할수록 점수가 오르게 함.

See: wiki/sources/incidents/2026_04_20_brain_prompt_prison.md
"""
from __future__ import annotations

from vxis.scoring.engine import ScoringEngine
from vxis.scoring.tracker import AttackChain, ChainStep, ScoreTracker


def _make_tracker_with_chain(depth: int, max_level: int = 1, chain_count: int = 1) -> ScoreTracker:
    """Build tracker with N chains of given depth; max step.level in each chain = max_level."""
    tr = ScoreTracker(target_type="web")
    for c in range(chain_count):
        ac = AttackChain(chain_id=f"chain-{c}")
        for i in range(depth):
            # Give last step the max_level so `any step.level >= X` triggers
            lvl = max_level if i == depth - 1 else 0
            ac.steps.append(ChainStep(
                step_index=i,
                vector_id="WEB-CHAIN",
                finding_id=f"f-{c}-{i}",
                level=lvl,
                description_en=f"step {i}",
                description_ko=f"단계 {i}",
            ))
        tr.attack_chains.append(ac)
    return tr


def _ci_score(tracker: ScoreTracker) -> float:
    engine = ScoringEngine("web")
    return engine._calc_chain_intelligence(tracker).score


# ─── Zero / no-chain case ──────────────────────────────────────────────────


def test_no_chains_scores_zero() -> None:
    tr = ScoreTracker(target_type="web")
    assert _ci_score(tr) == 0.0


# ─── Depth gradient (each step matters) ────────────────────────────────────


def test_depth_gradient_is_monotonic() -> None:
    """깊이 1 < 2 < 3 < 4 — 매 step 마다 점수가 올라야.

    기존 구현은 1-2 steps 가 동일 50pt 였음 (flat). Brain 이 '2 step 만
    채우면 최대 보상' 으로 인식. gradient 로 각 step 가치 명시.
    """
    scores = [_ci_score(_make_tracker_with_chain(d)) for d in range(1, 6)]
    # Strict monotonic increase up to 5 depth
    for prev, curr in zip(scores, scores[1:]):
        assert curr > prev, f"not monotonic: {scores}"


def test_depth_5_without_crown_is_below_old_max() -> None:
    """5-step 체인만으로는 150 만점 불가 — crown 보너스 있어야 full score.

    이전: 5+ depth = 무조건 150. 새 설계: 5-depth 만 = 125, crown 도달
    시 +25 = 150. 체인 '끝까지' 간다는 직관 강화.
    """
    score = _ci_score(_make_tracker_with_chain(5))  # max_level=1 (medium)
    assert score < 150.0
    assert score >= 125.0  # 여전히 깊은 체인은 후한 점수


# ─── Chain count bonus ─────────────────────────────────────────────────────


def test_multiple_chains_score_higher_than_one() -> None:
    """같은 깊이여도 체인 개수 많으면 보상. Brain 이 병렬 체인 여러 개 구축하도록."""
    one = _ci_score(_make_tracker_with_chain(depth=3, chain_count=1))
    two = _ci_score(_make_tracker_with_chain(depth=3, chain_count=2))
    three = _ci_score(_make_tracker_with_chain(depth=3, chain_count=3))
    assert two > one
    assert three > two


def test_count_bonus_capped() -> None:
    """체인 10개여도 count_bonus 는 상한 — 무의미 체인 스팸 방지."""
    three = _ci_score(_make_tracker_with_chain(depth=3, chain_count=3))
    ten = _ci_score(_make_tracker_with_chain(depth=3, chain_count=10))
    # count bonus 상한 15pt — 3개에서 이미 15pt 근처 도달했으면 10개도 비슷
    assert ten - three <= 20.0


# ─── Crown bonus (impact-aware) ────────────────────────────────────────────


def test_crown_bonus_rewards_critical_chain() -> None:
    """같은 깊이 + 같은 개수여도 critical (level ≥ 3) step 있으면 보너스.

    Brain 의 진짜 목표는 "admin 권한 / RCE / DB dump" 도달. 체인이 거기 닿았는지
    아닌지가 핵심.
    """
    no_crown = _ci_score(_make_tracker_with_chain(depth=3, max_level=1))
    with_crown = _ci_score(_make_tracker_with_chain(depth=3, max_level=3))
    assert with_crown > no_crown
    assert with_crown - no_crown >= 20.0


def test_full_kill_chain_hits_max_150() -> None:
    """5+ depth + crown (level 3+) = 150 만점 — 기존 kill chain 최대값 보존.

    이전 step-function 의 '5+ steps full kill chain = 150' 경계 유지.
    """
    tr = _make_tracker_with_chain(depth=5, max_level=4, chain_count=2)
    score = _ci_score(tr)
    assert score == 150.0


def test_score_capped_at_150() -> None:
    """depth + count + crown 합이 150 초과해도 상한 (max_score) 유지."""
    tr = _make_tracker_with_chain(depth=10, max_level=4, chain_count=10)
    assert _ci_score(tr) == 150.0


# ─── Backward-compat scenarios ─────────────────────────────────────────────


def test_old_3_step_chain_score_not_regressed() -> None:
    """3-step 체인 (critical 포함) 은 기존 100pt 와 비슷한 범위여야.

    기존: 3-4 step = 100pt. 새: 3 depth + crown = 75 + 25 = 100. 동일.
    """
    score = _ci_score(_make_tracker_with_chain(depth=3, max_level=3))
    assert 95.0 <= score <= 115.0
