"""RFC 5011's state table, driven as the scenarios in its §6 drive it -- and a few
the table only implies.

The clock is injected everywhere, so the 30-day hold-downs run at test speed
without shortening anything the document checks: the hold-down is not a delay but
a *condition on what was seen in between* (§2.4.1¶1's "at least two validated
DNSKEY RRSets"), which is exactly what these tests take turns asserting. The
observations handed to the machine stand in for validated fetches (observe()'s
contract); what a test can never fake is the transitions themselves -- they come
straight from §4¶3's table.
"""

from namespy.maintenance import (
    KeyState,
    TrustPointMaintenance,
    query_interval,
    retry_interval,
)
from namespy.rdata import RData_DNSKEY

DAY = 86400.0


def _key(seed: int, flags: int = 257) -> RData_DNSKEY:  # 257 = ZSK + SEP
    return RData_DNSKEY(flags, 3, 8, bytes([seed]) * 32)


class TestStartingPoints:
    def test_configured_anchors_are_trusted_immediately(self):
        a = _key(1)
        machine = TrustPointMaintenance(".", configured=[a])
        assert machine.state_of(a) is KeyState.VALID
        assert [int(k.key_tag) for k in machine.trust_anchors()] == [a.key_tag]

    def test_only_sep_keys_are_tracked_at_all(self):
        zsk = _key(2, flags=256)  # a zone key, not an entry point
        machine = TrustPointMaintenance(".")
        machine.observe([zsk], validated_by={zsk.key_tag}, now=0.0)
        assert machine.state_of(zsk) is None  # never entered the table (§2¶1)
        assert machine.trust_anchors() == []


class TestAddHoldDown:
    def test_a_new_key_needs_two_validated_sightings_across_the_hold_down(self):
        """§2.4.1¶1 states the purpose in the open: at least two RRSets, spanning time."""
        a, b = _key(1), _key(2)
        machine = TrustPointMaintenance(".", configured=[a])
        machine.observe([a, b], validated_by={a.key_tag}, now=0.0)
        assert machine.state_of(b) is KeyState.ADD_PENDING
        assert [int(k.key_tag) for k in machine.trust_anchors()] == [a.key_tag]
        machine.observe([a, b], validated_by={a.key_tag}, now=15 * DAY)
        assert machine.state_of(b) is KeyState.ADD_PENDING  # one day short
        final = machine.observe([a, b], validated_by={a.key_tag}, now=31 * DAY)
        assert machine.state_of(b) is KeyState.VALID
        assert any("AddPend -> Valid" in step for step in final)

    def test_absence_during_the_hold_down_resets_the_timer(self):
        """§2.2¶2: "it stops the acceptance process for that key and resets the timer"."""
        a, b = _key(1), _key(2)
        machine = TrustPointMaintenance(".", configured=[a])
        machine.observe([a, b], validated_by={a.key_tag}, now=0.0)
        machine.observe([a], validated_by={a.key_tag}, now=20 * DAY)
        assert machine.state_of(b) is KeyState.START
        machine.observe([a, b], validated_by={a.key_tag}, now=25 * DAY)
        # 25 + 30 = 55: at day 50 the 30-day clock from the *first* sighting
        # would have expired -- the reset is what keeps it pending.
        machine.observe([a, b], validated_by={a.key_tag}, now=50 * DAY)
        assert machine.state_of(b) is KeyState.ADD_PENDING
        machine.observe([a, b], validated_by={a.key_tag}, now=56 * DAY)
        assert machine.state_of(b) is KeyState.VALID

    def test_a_longer_original_ttl_sets_the_floor(self):
        """§2.4.1¶1's greater-of: 45-day TTL beats the 30-day minimum."""
        a, b = _key(1), _key(2)
        machine = TrustPointMaintenance(".", configured=[a])
        machine.observe([a, b], validated_by={a.key_tag}, orig_ttl=45 * DAY, now=0.0)
        machine.observe([a, b], validated_by={a.key_tag}, now=31 * DAY)
        assert machine.state_of(b) is KeyState.ADD_PENDING
        machine.observe([a, b], validated_by={a.key_tag}, now=46 * DAY)
        assert machine.state_of(b) is KeyState.VALID

    def test_five_pending_keys_is_the_floor_and_no_ceiling(self):
        """§2.4.3¶1: "MUST be able to manage at least five SEP keys per trust point"."""
        a = _key(1)
        keys = [_key(seed) for seed in range(2, 7)]
        machine = TrustPointMaintenance(".", configured=[a])
        machine.observe([a, *keys], validated_by={a.key_tag}, now=0.0)
        assert all(machine.state_of(k) is KeyState.ADD_PENDING for k in keys)
        machine.observe([a, *keys], validated_by={a.key_tag}, now=31 * DAY)
        assert all(machine.state_of(k) is KeyState.VALID for k in keys)


class TestRevocation:
    def test_a_self_signed_revoke_bit_is_immediate_and_drops_the_anchor(self):
        """§2.1¶2: seeing REVOKE plus a self-signature ends the key on the spot."""
        a, b = _key(1), _key(2)
        machine = TrustPointMaintenance(".", configured=[a, b])
        a_revoked = _key(1, flags=257 | 0x0080)
        assert a_revoked.key_tag != a.key_tag  # §2.1¶4's changed fingerprint
        trace = machine.observe(
            [a_revoked, b], validated_by={a_revoked.key_tag, b.key_tag}, now=10 * DAY
        )
        assert machine.state_of(a_revoked) is KeyState.REVOKED
        assert not any(int(k.key_tag) == a_revoked.key_tag for k in machine.trust_anchors())
        assert any("Revoked (RevBit)" in step for step in trace)

    def test_the_revoke_bit_alone_revokes_nothing_without_the_self_signature(self):
        """§3¶1's AND: the bit only bites when RRSIG(DNSKEY) by that key is seen."""
        a, b = _key(1), _key(2)
        machine = TrustPointMaintenance(".", configured=[a, b])
        a_revoked = _key(1, flags=257 | 0x0080)
        machine.observe([a_revoked, b], validated_by={b.key_tag}, now=10 * DAY)
        assert machine.state_of(a_revoked) is KeyState.VALID  # no RevBit event fired

    def test_a_pending_addition_dies_when_its_only_validator_is_revoked(self):
        """§2.2¶2's last clause, and order-independent: the same observation can
        both revoke A and judge B against that revocation (§6.4's shape)."""
        a, b, c = _key(1), _key(2), _key(3)
        machine = TrustPointMaintenance(".", configured=[a])
        machine.observe([a, b], validated_by={a.key_tag}, now=0.0)
        assert machine.state_of(b) is KeyState.ADD_PENDING
        a_revoked = _key(1, flags=257 | 0x0080)
        machine.observe(
            [b, a_revoked, c],  # B listed first on purpose: order must not matter
            validated_by={a_revoked.key_tag, c.key_tag},
            now=10 * DAY,
        )
        assert machine.state_of(a_revoked) is KeyState.REVOKED
        assert machine.state_of(b) is KeyState.START  # acceptance reset (§2.2¶2)
        assert machine.state_of(c) is KeyState.ADD_PENDING
        # C arrives in the same observation: its validators include the revoked A,
        # but also C's own self-signature, and an honest co-signer keeps the
        # hold-down running -- §2.2¶2 resets only when *all* validators are revoked.

    def test_revocation_reaches_a_key_never_trusted_before(self):
        """§3¶1 guards "this key permanently invalid", not "this trust anchor"."""
        a = _key(1)
        machine = TrustPointMaintenance(".", configured=[a])
        e_revoked = _key(5, flags=257 | 0x0080)
        machine.observe([a, e_revoked], validated_by={a.key_tag, e_revoked.key_tag}, now=0.0)
        assert machine.state_of(e_revoked) is KeyState.REVOKED
        plain = _key(5)  # the bit unset again -- a tombstone stays a tombstone
        machine.observe([a, plain], validated_by={a.key_tag}, now=5 * DAY)
        assert machine.state_of(plain) is KeyState.REVOKED


class TestAbsence:
    def test_a_missing_anchor_is_still_trusted_and_a_returning_one_is_whole(self):
        """§4.2¶4's abnormal-but-valid state, which §2.1¶1's threat model requires."""
        a, c = _key(1), _key(3)
        machine = TrustPointMaintenance(".", configured=[a])
        machine.observe([c], validated_by={c.key_tag}, now=0.0)
        assert machine.state_of(a) is KeyState.MISSING
        assert [int(k.key_tag) for k in machine.trust_anchors()] == [a.key_tag]
        machine.observe([a, c], validated_by={a.key_tag, c.key_tag}, now=5 * DAY)
        assert machine.state_of(a) is KeyState.VALID

    def test_a_revoked_key_absent_past_the_remove_hold_down_becomes_removed(self):
        a, b = _key(1), _key(2)
        machine = TrustPointMaintenance(".", configured=[a, b])
        a_revoked = _key(1, flags=257 | 0x0080)
        machine.observe([a_revoked, b], validated_by={a_revoked.key_tag, b.key_tag}, now=0.0)
        machine.observe([b], validated_by={b.key_tag}, now=5 * DAY)  # absent_since
        assert machine.state_of(a_revoked) is KeyState.REVOKED
        machine.observe([b], validated_by={b.key_tag}, now=36 * DAY)  # 31 days absent
        assert machine.state_of(a_revoked) is KeyState.REMOVED

    def test_removed_is_terminal_even_when_the_key_comes_back(self):
        """§4.2¶6: re-introducing previously used keys is the bad practice kept as
        a holding state precisely so the table has no way back."""
        a, b = _key(1), _key(2)
        machine = TrustPointMaintenance(".", configured=[a, b])
        a_revoked = _key(1, flags=257 | 0x0080)
        machine.observe([a_revoked, b], validated_by={a_revoked.key_tag, b.key_tag}, now=0.0)
        machine.observe([b], validated_by={b.key_tag}, now=5 * DAY)
        machine.observe([b], validated_by={b.key_tag}, now=36 * DAY)
        assert machine.state_of(a_revoked) is KeyState.REMOVED
        machine.observe([_key(1), b], validated_by={b.key_tag}, now=40 * DAY)
        assert machine.state_of(a_revoked) is KeyState.REMOVED


class TestTrustPointDeletion:
    def test_an_all_revoked_trust_point_is_deleted_while_a_pending_key_is_not_an_anchor(self):
        """§5¶1's quantifier covers trust anchors -- and a pending key is not one."""
        a, b = _key(1), _key(2)
        machine = TrustPointMaintenance(".", configured=[a])
        assert not machine.trust_point_deleted()
        a_revoked = _key(1, flags=257 | 0x0080)
        machine.observe([a_revoked, b], validated_by={a_revoked.key_tag}, now=0.0)
        assert machine.state_of(b) is KeyState.ADD_PENDING
        assert machine.trust_point_deleted()  # no anchor stands; B is still a candidate

    def test_a_subordinate_point_becomes_deletable_180_days_after_everything_is_removed(self):
        """§5¶2's MAY, exposed as a predicate; the decision stays the operator's."""
        a, b = _key(1), _key(2)
        machine = TrustPointMaintenance(".", configured=[a, b])
        for seed in (1, 2):
            revoked = _key(seed, flags=257 | 0x0080)
            machine.observe(
                [revoked, _key(3 - seed)],
                validated_by={revoked.key_tag},
                now=0.0,
            )
        machine.observe([], validated_by=set(), now=5 * DAY)
        assert not machine.deletable_subordinate(36 * DAY)
        machine.observe([], validated_by=set(), now=36 * DAY)
        machine.observe([], validated_by=set(), now=37 * DAY)  # both now Removed
        assert all(
            machine.state_of(_key(seed, flags=257 | 0x0080)) is KeyState.REMOVED for seed in (1, 2)
        )
        assert not machine.deletable_subordinate(100 * DAY)  # 63 days: not yet
        assert machine.deletable_subordinate(220 * DAY)  # 183 days: the 180 have passed


class TestPersistence:
    def test_the_database_survives_a_restart_with_its_timers(self):
        """§2.2¶4 is a cross-restart promise: Valid stays Valid, AddPend keeps its clock."""
        a, b = _key(1), _key(2)
        machine = TrustPointMaintenance(".", configured=[a])
        machine.observe([a, b], validated_by={a.key_tag}, now=0.0)
        revived = TrustPointMaintenance.from_document(machine.to_document())
        assert revived.state_of(b) is KeyState.ADD_PENDING
        assert revived.state_of(a) is KeyState.VALID
        revived.observe([a, b], validated_by={a.key_tag}, now=31 * DAY)
        assert revived.state_of(b) is KeyState.VALID  # deadline kept across the restart
        assert [int(k.key_tag) for k in revived.trust_anchors()] == sorted([a.key_tag, b.key_tag])


class TestCadence:
    def test_query_interval_is_the_formulas_three_bounds(self):
        """§2.3¶1: MAX(1 hr, MIN(15 days, ttl/2, exp/2)), floor and ceiling both live."""
        assert query_interval(60, [3600]) == 3600.0  # short everything -> 1 hr floor
        assert query_interval(100 * DAY, [80 * DAY]) == 15 * DAY  # 15-day ceiling
        assert query_interval(40 * DAY, [10 * DAY]) == 5 * DAY  # the RRSIG bound wins
        assert query_interval(40 * DAY, [10 * DAY, 100 * DAY]) == 5 * DAY  # tightest

    def test_retry_interval_is_the_same_shape_at_one_day(self):
        """§2.3¶2: MAX(1 hour, MIN(1 day, .1*ttl, .1*exp))."""
        assert retry_interval(10 * DAY, [20 * DAY]) == 86400.0  # 1-day ceiling
        assert retry_interval(3600, [3600]) == 3600.0  # 1-hour floor
        assert retry_interval(5 * DAY, [10 * DAY]) == 12 * 3600.0  # .1 * 5 days


class TestRolloverScenario:
    def test_a_full_rollover_from_old_to_new_key(self):
        """§6.3 at test speed: add, hold, accept, revoke, retire -- one anchor throughout."""
        old, new = _key(1), _key(2)
        machine = TrustPointMaintenance(".", configured=[old])
        machine.observe([old, new], validated_by={old.key_tag}, now=0.0)
        for day in (16, 31):  # seen in every validated RRSet across the hold-down
            machine.observe([old, new], validated_by={old.key_tag}, now=day * DAY)
        assert machine.state_of(new) is KeyState.VALID
        assert machine.state_of(old) is KeyState.VALID  # never trusted less by absence
        # The ceremony ends: old key revoked, self-signed, as §6.3 describes.
        old_revoked = _key(1, flags=257 | 0x0080)
        machine.observe(
            [old_revoked, new], validated_by={old_revoked.key_tag, new.key_tag}, now=35 * DAY
        )
        assert machine.state_of(old_revoked) is KeyState.REVOKED
        assert [int(k.key_tag) for k in machine.trust_anchors()] == [new.key_tag]
        machine.observe([new], validated_by={new.key_tag}, now=40 * DAY)
        machine.observe([new], validated_by={new.key_tag}, now=71 * DAY)
        assert machine.state_of(old_revoked) is KeyState.REMOVED
        assert not machine.trust_point_deleted()  # one anchor still stands
