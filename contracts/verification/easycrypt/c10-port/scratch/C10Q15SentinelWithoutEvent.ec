require import AllCore List Distr FMap StdOrder DList DBool.
require import C10RawOracle C10Counter C10Bytes C10Randomizer C10RawGrind RawKeygen PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion FullSession FullSessionCost FullPrefix ByteSession ByteBound.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicCollisionState BytePublicCollision.
require import RawWots PersistentGrind RawCountRecorded WotsReferenceRoot RawWotsRecovery WotsZeroSentinel PublicNodeZero BytePublicNodeBad.
import RealOrder.
lemma drops_event seed0 layer0 tree0 kp0 message0 count0 d0 h0 s0 root0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ count=count0 /\
    !count_accepts d0 /\ h0.[wots_count_input seed0 layer0 tree0 kp0 message0 count0]=Some d0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    wots_root h0 s0 seed0 layer0 tree0 kp0 root0 ==>
    res<>root0].
proof. exact (invalid_sum_matches_only_zero seed0 layer0 tree0 kp0 message0 count0 d0 h0 s0 root0). qed.
