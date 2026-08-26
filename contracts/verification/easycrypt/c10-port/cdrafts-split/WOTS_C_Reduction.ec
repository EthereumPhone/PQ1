(* ==========================================================================
   WOTS_C_Reduction.ec  --  The Algorithm-9 reduction for Thm C.2
                            (single-instance WOTS+C EU-naCMA).

   Builds on WOTS_C_Scheme.ec.  Two real, zero-admit module definitions:
     * EUF_NACMA_WOTSC — the single-instance, one-query WOTS+C EU-naCMA game
       (paper Exp^{EU-naCMA}_{WOTS+C}), the LHS of Thm C.2;
     * R_STCRC_WOTSC   — the S-TCR(+C) reduction (paper Algorithm 9).

   The "public-seed availability" question is resolved by the naCMA structure:
   the adversary commits to its message in `choose()` BEFORE the public key
   exists, so the reduction registers the S-TCR target at `pick()` time and
   DEFERS building the keypair + signature to `find(pp)`, where `pp` is the
   revealed public seed.  Because `grind` is the same deterministic op the
   S-TCR oracle uses, the counter the oracle recorded at `pick` equals the one
   `WOTS_C_ES.sign` reproduces at `find` — the target and the signature agree.
   ========================================================================== *)

require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme.

import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import WOTS_C_Scheme.

(* --------------------------------------------------------------------------
   The single-instance, one-query WOTS+C EU-naCMA game (LHS of Thm C.2).
   Non-adaptive: A commits to its message in `choose()` before seeing the pk.
   -------------------------------------------------------------------------- *)
module type Adv_EUFNACMA_WOTSC(OC : STCRC_WC.Col.Oracle_THFC) = {
  proc choose() : dgstblock { OC.query }
  proc forge(pk : pkWOTSTW, sig : sigWOTS * cntr) : dgstblock * (sigWOTS * cntr) {}
}.

module EUF_NACMA_WOTSC(A : Adv_EUFNACMA_WOTSC, OC : STCRC_WC.Col.Oracle_THFC) = {
  module AA = A(OC)

  proc main() : bool = {
    var ps : pseed;
    var pk : pkWOTSTW;
    var sk : skWOTS * pseed * adrs;
    var m, m' : dgstblock;
    var sigc, sigc' : sigWOTS * cntr;
    var is_valid : bool;

    ps <$ dpseed;
    OC.init(ps);

    m <@ AA.choose();                        (* commit to the message (non-adaptive) *)
    (pk, sk) <@ WOTS_C_ES.keygen(ps, witness);
    sigc <@ WOTS_C_ES.sign(sk, m);
    (m', sigc') <@ AA.forge(pk, sigc);

    is_valid <@ WOTS_C_ES.verify(pk, m', sigc');
    return m' <> m /\ is_valid;
  }
}.

(* --------------------------------------------------------------------------
   Algorithm 9 — the S-TCR(+C) reduction.  R is an S-TCR(+C) adversary that
   wraps the WOTS+C forger A.  `witness : adrs` is the single instance's fixed
   context T* (any fixed WOTS address; the proof does not depend on which).
   -------------------------------------------------------------------------- *)
module (R_STCRC_WOTSC (A : Adv_EUFNACMA_WOTSC) : STCRC_WC.Adv_STCRC)
       (O : STCRC_WC.Oracle_STCRC, OC : STCRC_WC.Col.Oracle_THFC) = {
  module AA = A(OC)
  var mm : dgstblock

  (* Step 1-4: get A's committed message, register the S-TCR(+C) target
     (T*, mm) with the challenger (grinds a good counter, records it). *)
  proc pick() : unit = {
    var y : msgWOTS;      (* the S-TCR(+C) oracle returns the digest *)
    var i : cntr;
    mm <@ AA.choose();
    (y, i) <@ O.query(witness, mm);
  }

  (* Step 5-12: with the revealed public seed pp, build the WOTS+C keypair and
     the signature for mm (WOTS_C_ES.sign reproduces the recorded counter since
     `grind` is deterministic), hand them to A, and relay A's forgery as the
     candidate S-TCR(+C) collision (target index 0). *)
  proc find(pp : pseed) : int * dgstblock * cntr = {
    var pk : pkWOTSTW;
    var sk : skWOTS * pseed * adrs;
    var sigc, sigc' : sigWOTS * cntr;
    var m' : dgstblock;

    (pk, sk) <@ WOTS_C_ES.keygen(pp, witness);
    sigc <@ WOTS_C_ES.sign(sk, mm);
    (m', sigc') <@ AA.forge(pk, sigc);

    return (0, m', sigc'.`2);
  }
}.

(* --------------------------------------------------------------------------
   GAME.1 (paper Thm C.2 proof): GAME.0 with the extra loss condition "a Th
   collision is extractable from the signature and the forgery"
   (Th(P,T*,m‖i) = Th(P,T*,m'‖j)).  The GAME.0 -> GAME.1 gap is what the S-TCR(+C)
   reduction bounds.
   -------------------------------------------------------------------------- *)
module GAME1_WOTSC(A : Adv_EUFNACMA_WOTSC, OC : STCRC_WC.Col.Oracle_THFC) = {
  module AA = A(OC)

  proc main() : bool = {
    var ps : pseed;
    var pk : pkWOTSTW;
    var sk : skWOTS * pseed * adrs;
    var m, m' : dgstblock;
    var sigc, sigc' : sigWOTS * cntr;
    var is_valid : bool;

    ps <$ dpseed;
    OC.init(ps);

    m <@ AA.choose();
    (pk, sk) <@ WOTS_C_ES.keygen(ps, witness);
    sigc <@ WOTS_C_ES.sign(sk, m);
    (m', sigc') <@ AA.forge(pk, sigc);

    is_valid <@ WOTS_C_ES.verify(pk, m', sigc');
    return    m' <> m /\ is_valid
           /\ ! (ThC ps witness m sigc.`2 = ThC ps witness m' sigc'.`2);
  }
}.

(* GAME.0 instrumented: identical to EUF_NACMA_WOTSC but records the collision
   event `coll` in a global so it is observable in Pr[...].  The extra assignment
   does not touch the returned bit, so Pr[EUF_NACMA : res] = Pr[G0_inst : res]. *)
module G0_inst(A : Adv_EUFNACMA_WOTSC, OC : STCRC_WC.Col.Oracle_THFC) = {
  module AA = A(OC)
  var coll : bool

  proc main() : bool = {
    var ps : pseed;
    var pk : pkWOTSTW;
    var sk : skWOTS * pseed * adrs;
    var m, m' : dgstblock;
    var sigc, sigc' : sigWOTS * cntr;
    var is_valid : bool;

    ps <$ dpseed;
    OC.init(ps);

    m <@ AA.choose();
    (pk, sk) <@ WOTS_C_ES.keygen(ps, witness);
    sigc <@ WOTS_C_ES.sign(sk, m);
    (m', sigc') <@ AA.forge(pk, sigc);

    is_valid <@ WOTS_C_ES.verify(pk, m', sigc');
    coll <- (ThC ps witness m sigc.`2 = ThC ps witness m' sigc'.`2);
    return m' <> m /\ is_valid;
  }
}.

(* Functional fact about the honest signer: the counter it emits is exactly the
   deterministic grind of (ps, ad, m).  Used to identify sigc.`2 (side 1) with the
   S-TCR target's recorded counter j = grind pp witness mm (side 2).  The chain
   walk (the `while`) never touches `counter`, so it is a trivial loop invariant. *)
lemma sign_ctr (sk0 : skWOTS * pseed * adrs) (m0 : dgstblock) :
  hoare[WOTS_C_ES.sign : sk = sk0 /\ m = m0 ==> res.`2 = grindC sk0.`2 sk0.`3 m0].
proof.
  proc; while (counter = grindC sk0.`2 sk0.`3 m0); by auto.
qed.

(* keygen / sign are deterministic-shaped shared calls: two runs on equal inputs
   agree (keygen's only sampling is `dskWOTS`, coupled by `sim`; sign has none). *)
equiv keygen_eq : WOTS_C_ES.keygen ~ WOTS_C_ES.keygen : ={arg} ==> ={res}.
proof. proc; sim. qed.

equiv sign_eq : WOTS_C_ES.sign ~ WOTS_C_ES.sign : ={arg} ==> ={res}.
proof. proc; sim. qed.

(* keygen threads the address through unchanged: sk = (_, ps, ad). *)
lemma keygen_sk (ps0 : pseed) (ad0 : adrs) :
  hoare[WOTS_C_ES.keygen : ps = ps0 /\ ad = ad0 ==> (res.`2).`2 = ps0 /\ (res.`2).`3 = ad0].
proof. proc; inline*; wp; while (ps = ps0 /\ ad = ad0); auto. qed.

(* keygen threads the address through unchanged (address-only variant, so the
   public seed — which is the coupled random sample — need not be snapshotted). *)
lemma keygen_ad (ad0 : adrs) :
  hoare[WOTS_C_ES.keygen : ad = ad0 ==> (res.`2).`3 = ad0].
proof. proc; inline*; wp; while (ad = ad0); auto. qed.

(* keygen, combined: equal outputs AND the secret-key carries the address. *)
equiv keygen_eqad (ad0 : adrs) : WOTS_C_ES.keygen ~ WOTS_C_ES.keygen :
  ={arg} /\ ad{2} = ad0 ==> ={res} /\ (res{2}.`2).`3 = ad0.
proof. conseq keygen_eq (_ : true ==> true) (keygen_ad ad0) => //. qed.

(* keygen, combined: equal outputs AND the secret-key carries (ps, ad) — the
   values passed as CONSTANTS so the fact chains into sign_eqs2 without a
   fresh-var snapshot (which disconnects from the quantified keygen result). *)
equiv keygen_eqs (ps0 : pseed) (ad0 : adrs) : WOTS_C_ES.keygen ~ WOTS_C_ES.keygen :
  ={arg} /\ ps{2} = ps0 /\ ad{2} = ad0
  ==> ={res} /\ (res{2}.`2).`2 = ps0 /\ (res{2}.`2).`3 = ad0.
proof. conseq keygen_eq (_ : true ==> true) (keygen_sk ps0 ad0) => //. qed.

(* sign, combined: equal outputs AND the counter is the deterministic grind. *)
equiv sign_eqs (sk0 : skWOTS * pseed * adrs) (m0 : dgstblock) : WOTS_C_ES.sign ~ WOTS_C_ES.sign :
  ={arg} /\ sk{2} = sk0 /\ m{2} = m0
  ==> ={res} /\ res{2}.`2 = grindC (sk0.`2) (sk0.`3) m0.
proof. conseq sign_eq (_ : true) (sign_ctr sk0 m0) => //. qed.

(* sign counter in terms of the CONSTANTS (ps0, ad0, m0) — the pre `sk.`2 = ps0`
   is exactly what keygen_eqs establishes, so the two chain through constants. *)
lemma sign_ctr2 (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock) :
  hoare[WOTS_C_ES.sign :
          sk.`2 = ps0 /\ sk.`3 = ad0 /\ m = m0 ==> res.`2 = grindC ps0 ad0 m0].
proof. proc; while (counter = grindC ps0 ad0 m0); by auto. qed.

equiv sign_eqs2 (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock) : WOTS_C_ES.sign ~ WOTS_C_ES.sign :
  ={arg} /\ sk{2}.`2 = ps0 /\ sk{2}.`3 = ad0 /\ m{2} = m0
  ==> ={res} /\ res{2}.`2 = grindC ps0 ad0 m0.
proof. conseq sign_eq (_ : true ==> true) (sign_ctr2 ps0 ad0 m0) => //. qed.

(* The signer's grind and the S-TCR oracle's grind are the SAME op (grindC is
   defined as G.grind), so the honest counter = the recorded S-TCR target counter. *)
lemma grindC_E (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock) :
  grindC ps0 ad0 m0 = STCRC_WC.G.grind ps0 ad0 m0.
proof. by rewrite /grindC. qed.

(* verify terminates (spare on the LHS: is_valid is unused in the implication). *)
lemma verify_ll : islossless WOTS_C_ES.verify.
proof. islossless; while true (len - size pkWOTS_l); auto; smt(size_rcons). qed.

(* The reduction bound: the collision part of GAME.0 is caught by the S-TCR(+C)
   game through R_STCRC_WOTSC.  This is the core pRHL of Algorithm 9. *)
lemma WOTSC_C2_reduce (A <: Adv_EUFNACMA_WOTSC{-R_STCRC_WOTSC, -STCRC_WC.O_STCRC_Default, -STCRC_WC.Col.O_THFC_Default, -G0_inst}) &m :
    (* (a) target-count assumption: the reduction places exactly one S-TCR(+C)
       target, so the game's cap `nrts <= p_stcr` needs `1 <= p_tgts` (= p_stcr).
       Trivially true in any real SPHINCS+ instantiation (q6 >= 1). *)
    1 <= p_tgts =>
    (* (b) address separation: the WOTS+C forger A never queries the Th_lambda
       collection oracle at the challenge tweak `witness` (A queries OC only in
       `choose`, which runs from the fresh `tws = []`).  Faithful to the paper's
       DIST condition; discharges `disj_lists [witness] OC.tws`. *)
    hoare[A(STCRC_WC.Col.O_THFC_Default).choose :
            STCRC_WC.Col.O_THFC_Default.tws = []
            ==> ! (witness \in STCRC_WC.Col.O_THFC_Default.tws)] =>
    Pr[G0_inst(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res /\ G0_inst.coll]
  <= Pr[STCRC_WC.S_TCR_C(R_STCRC_WOTSC(A),
                         STCRC_WC.O_STCRC_Default,
                         STCRC_WC.Col.O_THFC_Default).main() @ &m : res].
proof.
  move=> le1_ptgts sep.
  byequiv (_ : ={glob A} ==> (res{1} /\ G0_inst.coll{1}) => res{2}) => //.
  proc.
  inline{2} R_STCRC_WOTSC(A, STCRC_WC.O_STCRC_Default, STCRC_WC.Col.O_THFC_Default).pick.
  inline{2} R_STCRC_WOTSC(A, STCRC_WC.O_STCRC_Default, STCRC_WC.Col.O_THFC_Default).find.
  inline{2} STCRC_WC.O_STCRC_Default.init STCRC_WC.O_STCRC_Default.query
            STCRC_WC.O_STCRC_Default.get STCRC_WC.O_STCRC_Default.nr_targets
            STCRC_WC.O_STCRC_Default.dist_tweaks STCRC_WC.O_STCRC_Default.get_tweaks
            STCRC_WC.Col.O_THFC_Default.get_tweaks.
  inline{1} STCRC_WC.Col.O_THFC_Default.init.
  inline{2} STCRC_WC.Col.O_THFC_Default.init.
  (* choose perfectly simulated, AND (via `sep`) A never touches the tweak
     `witness` on the collection oracle, so `disj_lists [witness] OC.tws` holds. *)
  have ch_eq :
    equiv[A(STCRC_WC.Col.O_THFC_Default).choose ~ A(STCRC_WC.Col.O_THFC_Default).choose :
            ={glob A, glob STCRC_WC.Col.O_THFC_Default}
            ==> ={glob A, glob STCRC_WC.Col.O_THFC_Default, res}].
  + by sim.
  have choose_sep :
    equiv[A(STCRC_WC.Col.O_THFC_Default).choose ~ A(STCRC_WC.Col.O_THFC_Default).choose :
            ={glob A, glob STCRC_WC.Col.O_THFC_Default}
            /\ STCRC_WC.Col.O_THFC_Default.tws{2} = []
            ==> ={glob A, glob STCRC_WC.Col.O_THFC_Default, res}
                /\ ! (witness \in STCRC_WC.Col.O_THFC_Default.tws{2})].
  + conseq ch_eq (: true ==> true) sep => //.
  (* Sample-first coupling: fix the public seed as an EQUAL variable (ps{1}=pp{2})
     BEFORE any snapshot, so `exists*` on the seed post-`rnd` is a genuine value
     and the counter=grind identity threads through CONSTANTS. *)
  seq 1 1 : (={glob A} /\ ps{1} = pp{2}).
  + rnd; skip => />.
  seq 3 6 : (={glob A} /\ ps{1} = pp{2} /\ ={glob STCRC_WC.Col.O_THFC_Default}
             /\ STCRC_WC.Col.O_THFC_Default.tws{2} = []
             /\ STCRC_WC.O_STCRC_Default.pp{2} = pp{2}
             /\ STCRC_WC.O_STCRC_Default.ts{2} = []).
  + auto => />.
  seq 1 1 : (={glob A} /\ ps{1} = pp{2} /\ ={glob STCRC_WC.Col.O_THFC_Default}
             /\ STCRC_WC.O_STCRC_Default.pp{2} = pp{2}
             /\ STCRC_WC.O_STCRC_Default.ts{2} = []
             /\ m{1} = R_STCRC_WOTSC.mm{2}
             /\ ! (witness \in STCRC_WC.Col.O_THFC_Default.tws{2})).
  + call choose_sep; skip => />.
  (* Now snapshot the (already-sampled) seed and message as constants, and thread
     keygen's structure into sign's counter through them (no fresh-var disconnect). *)
  exists* pp{2}, R_STCRC_WOTSC.mm{2}; elim* => ppv mmv.
  wp.
  call{1} verify_ll.
  call (_: true).
  call (sign_eqs2 ppv witness mmv).
  call (keygen_eqs ppv witness).
  wp.
  skip => /> *.
  smt(grindC_E).
qed.

(* Thm C.2, first game-hop.  GAME.0 <= GAME.1 + InSec^{S-TCR(+C)} via the
   Algorithm-9 reduction R_STCRC_WOTSC.  Structure: instrument GAME.0, split on
   the collision event; the no-collision part IS GAME.1, the collision part is
   the reduction (`WOTSC_C2_reduce`, the remaining pRHL obligation). *)
lemma WOTSC_C2_hop1 (A <: Adv_EUFNACMA_WOTSC{-R_STCRC_WOTSC, -STCRC_WC.O_STCRC_Default, -STCRC_WC.Col.O_THFC_Default, -G0_inst}) &m :
    1 <= p_tgts =>
    hoare[A(STCRC_WC.Col.O_THFC_Default).choose :
            STCRC_WC.Col.O_THFC_Default.tws = []
            ==> ! (witness \in STCRC_WC.Col.O_THFC_Default.tws)] =>
    Pr[EUF_NACMA_WOTSC(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
  <=   Pr[GAME1_WOTSC(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
     + Pr[STCRC_WC.S_TCR_C(R_STCRC_WOTSC(A),
                           STCRC_WC.O_STCRC_Default,
                           STCRC_WC.Col.O_THFC_Default).main() @ &m : res].
proof.
  move=> le1_ptgts sep.
  (* instrument: Pr[GAME.0 : res] = Pr[G0_inst : res] *)
  have e0 : Pr[EUF_NACMA_WOTSC(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
          = Pr[G0_inst(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res].
  + byequiv => //; proc; wp; sim.
  rewrite e0 Pr[mu_split (G0_inst.coll)].
  (* the no-collision part IS GAME.1 *)
  have e1 : Pr[G0_inst(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res /\ !G0_inst.coll]
          = Pr[GAME1_WOTSC(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res].
  + byequiv => //; proc.
    seq 7 7 : (={ps, m, m', sigc, sigc', is_valid} /\ ={glob STCRC_WC.Col.O_THFC_Default}).
    + sim.
    wp; skip => />; smt().
  rewrite e1.
  (* the collision part is the reduction *)
  have e2 := WOTSC_C2_reduce A &m le1_ptgts sep.
  smt().
qed.

(* ==========================================================================
   Thm C.2 second game-hop (Algorithm 10, WOTS-TW reduction).
   GAME.1 <= InSec^{EU-naCMA}(WOTS-TW).  Modeling choices (explicit; the proof
   is now zero-admit under the encode bridge, so these are the modeling
   reconciliation points, not hidden gaps):
     * single-instance WOTS-TW EU-naCMA game over the real WOTS_TW_ES_NPRF;
     * collection oracle unified to STCRC_WC.Col (the S-TCR collection) so the
       WOTS+C forger A and the reduction R agree — unifying this with the repo's
       FC (one Th_lambda over both the chain hash f and Th+C) is the remaining
       structural reconciliation;
     * the reduction grinds the seed via Th_lambda (OC) in choose() — pp is not
       yet revealed — and sends the digest d as the WOTS-TW signing message.
   ========================================================================== *)
module type Adv_EUFNACMA_WOTSTW(OC : STCRC_WC.Col.Oracle_THFC) = {
  proc choose() : msgWOTS { OC.query }
  proc forge(pk : pkWOTSTW, sig : sigWOTS) : msgWOTS * sigWOTS {}
}.

module EUF_NACMA_WOTSTW(A : Adv_EUFNACMA_WOTSTW, OC : STCRC_WC.Col.Oracle_THFC) = {
  module AA = A(OC)

  proc main() : bool = {
    var ps : pseed;
    var pk : pkWOTSTW;
    var sk : skWOTS * pseed * adrs;
    var m, m' : msgWOTS;     (* WOTS-TW signs ThC's OUTPUT *)
    var sig, sig' : sigWOTS;
    var is_valid : bool;

    ps <$ dpseed;
    OC.init(ps);

    m <@ AA.choose();
    (pk, sk) <@ WOTS_TW_ES_NPRF.keygen(ps, witness);
    sig <@ WOTS_TW_ES_NPRF.sign(sk, m);
    (m', sig') <@ AA.forge(pk, sig);

    is_valid <@ WOTS_TW_ES_NPRF.verify(pk, m', sig');
    return m' <> m /\ is_valid;
  }
}.

(* Algorithm 10 — the WOTS-TW reduction.  R wraps the WOTS+C forger A; it grinds
   the +C seed via Th_lambda and drives the WOTS-TW challenger. *)
module (R_WOTSTW_WOTSC (A : Adv_EUFNACMA_WOTSC) : Adv_EUFNACMA_WOTSTW)
       (OC : STCRC_WC.Col.Oracle_THFC) = {
  module AA = A(OC)
  var mm  : dgstblock
  var sd  : cntr

  (* Grind a good seed via Th_lambda, then commit the digest at the grind seed
     UNIFORMLY: `d = ThC ps witness mm sd` where `sd = grind ps witness mm` (the
     TOTAL op, = `witness` on grind-fail — a well-defined value, NOT a sentinel).
     The final query realises `ThC ps witness mm sd` through the collection oracle
     (pp is naCMA-hidden in choose, so the digest must come from OC).  This makes
     the message R sends coincide with the honest WOTS+C signer's digest on EVERY
     path (found or fail), so the signing coupling never diverges. *)
  proc choose() : msgWOTS = {
    var cs : cntr list;
    var seed : cntr;
    var y, d : msgWOTS;      (* ThC outputs *)
    var found : bool;

    mm <@ AA.choose();
    cs <- STCRC_WC.G.CntrFT.enum;
    found <- false; sd <- witness;
    while (!found /\ cs <> []) {
      seed <- head witness cs;
      y <@ OC.query(witness, (mm, seed));
      if (predC y) { sd <- seed; found <- true; }
      cs <- behead cs;
    }
    d <@ OC.query(witness, (mm, sd));
    return d;
  }

  (* Bridge the WOTS-TW signature to a WOTS+C signature (sig, seed), relay A's
     forgery back as a WOTS-TW forgery ON THE DIGEST.  WOTS-TW verifies the raw
     message via `encode_msgWOTS`, whereas WOTS+C chain-walks `encode_msgWOTS_C`
     (= `encode_msgWOTS` of the digest `ThC ps witness m' counter'`, by the
     `encode_msgWOTS_C` construction).  So the faithful WOTS-TW forgery message is
     the digest of A's forgery, not A's raw message (pk.`2 = ps). *)
  proc forge(pk : pkWOTSTW, sig : sigWOTS) : msgWOTS * sigWOTS = {
    var m' : dgstblock;      (* A's +C message is a NODE; the DIGEST is returned *)
    var sigc' : sigWOTS * cntr;

    (m', sigc') <@ AA.forge(pk, (sig, sd));
    return (ThC pk.`2 witness m' sigc'.`2, sigc'.`1);
  }
}.

(* ---- hop2 modeling helpers (verifiable core of the Alg-10 reduction) -------
   WOTS+C and WOTS-TW share the SAME keygen and the SAME chain walk; they differ
   ONLY in the encoding.  These two lemmas isolate exactly that, so the remaining
   hop2 obligation is purely (i) the encode bridge (a faithful modeling fact:
   `encode_msgWOTS_C` is `encode_msgWOTS` of the +C digest, by construction) and
   (ii) the operational grind-search correctness. *)

(* grindC in the concrete filter/head form R.choose's scan produces. *)
lemma grindC_filter (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock) :
  grindC ps0 ad0 m0
  = head witness
      (filter (fun c => predC (ThC ps0 ad0 m0 c)) STCRC_WC.G.CntrFT.enum).
proof. by rewrite /grindC /STCRC_WC.G.grind /STCRC_WC.G.good_ctrs. qed.

(* keygen is literally shared: WOTS_C_ES.keygen wraps WOTS_TW_ES_NPRF.keygen. *)
equiv keygenC_TW : WOTS_C_ES.keygen ~ WOTS_TW_ES_NPRF.keygen : ={arg} ==> ={res}.
proof. proc*; inline{1} WOTS_C_ES.keygen; sim. qed.

lemma keygenTW_sk (ps0 : pseed) (ad0 : adrs) :
  hoare[WOTS_TW_ES_NPRF.keygen : ps = ps0 /\ ad = ad0
        ==> (res.`1).`2 = ps0 /\ (res.`1).`3 = ad0
            /\ (res.`2).`2 = ps0 /\ (res.`2).`3 = ad0].
proof. proc; inline*; wp; while (ps = ps0 /\ ad = ad0); auto. qed.

equiv keygenC_TW_s (ps0 : pseed) (ad0 : adrs) :
  WOTS_C_ES.keygen ~ WOTS_TW_ES_NPRF.keygen :
    ={arg} /\ ps{2} = ps0 /\ ad{2} = ad0
    ==> ={res} /\ (res{2}.`1).`2 = ps0 /\ (res{2}.`1).`3 = ad0
        /\ (res{2}.`2).`2 = ps0 /\ (res{2}.`2).`3 = ad0.
proof. conseq keygenC_TW (_ : true ==> true) (keygenTW_sk ps0 ad0) => //. qed.

(* Under the encode bridge, WOTS+C-signing a message `m0` produces byte-identical
   chains to WOTS-TW-signing the +C digest `ThC ps ad m0 (grindC ps ad m0)`, and
   the emitted counter is the grind.  This is the heart of Algorithm 10. *)
lemma signC_TW (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock) :
  (forall (p : pseed) (a : adrs) (x : dgstblock) (c : cntr),
     encode_msgWOTS_C p a x c = encode_msgWOTS (ThC p a x c)) =>
  equiv[WOTS_C_ES.sign ~ WOTS_TW_ES_NPRF.sign :
          ={sk} /\ sk{2}.`2 = ps0 /\ sk{2}.`3 = ad0 /\ m{1} = m0
          /\ m{2} = ThC ps0 ad0 m0 (grindC ps0 ad0 m0)
          ==> res{1}.`1 = res{2} /\ res{1}.`2 = grindC ps0 ad0 m0].
proof.
  move=> encb.
  proc.
  while (={sig, skWOTS} /\ ps{1} = ps{2} /\ ad{1} = ad{2} /\ em{1} = em{2}
         /\ counter{1} = grindC ps0 ad0 m0).
  + by auto.
  auto => />; smt().
qed.

(* Under the encode bridge, a valid WOTS+C signature on m' is a valid WOTS-TW
   signature on the +C digest (WOTS+C additionally gates on predC — strictly
   stronger, so validity transfers). *)
lemma verifyC_TW (psA : pseed) (adA : adrs) (mA : dgstblock) (cA : cntr) :
  (forall (p : pseed) (a : adrs) (x : dgstblock) (c : cntr),
     encode_msgWOTS_C p a x c = encode_msgWOTS (ThC p a x c)) =>
  equiv[WOTS_C_ES.verify ~ WOTS_TW_ES_NPRF.verify :
          ={pk} /\ pk{2}.`2 = psA /\ pk{2}.`3 = adA /\ m{1} = mA
          /\ sigc{1}.`2 = cA /\ sig{2} = sigc{1}.`1
          /\ m{2} = ThC psA adA mA cA
          ==> res{1} => res{2} /\ predC (ThC psA adA mA cA)].
proof.
  (* POST STRENGTHENED 2026-07-29.  It used to be just `res{1} => res{2}`, which
     THREW AWAY the +C gate: WOTS_C_ES.verify returns `pk-match /\ okC` with
     `okC = predC (ThC ps ad m counter)` (WOTS_C_Scheme.ec:101,103), and the old
     post discarded it.  interactive_hop2 needs exactly that conjunct for the
     FORGED digest under the gated WOTS-TW game, so it is now carried out. *)
  move=> encb; proc.
  inline{2} WOTS_TW_ES_NPRF.pkWOTS_from_sigWOTS.
  wp.
  while (pkWOTS_l{1} = pkWOTS0{2} /\ ps{1} = ps0{2} /\ ad{1} = ad0{2}
         /\ em{1} = em{2} /\ sig{1} = sig0{2}).
  + auto => />; smt().
  auto => />; smt().
qed.

(* Relational (paramless) verify cross-equiv — the WOTS-TW forgery message is the
   +C digest of A's forgery, stated directly so no `exists*` snapshot is needed. *)
lemma verifyC_TW2 :
  (forall (p : pseed) (a : adrs) (x : dgstblock) (c : cntr),
     encode_msgWOTS_C p a x c = encode_msgWOTS (ThC p a x c)) =>
  equiv[WOTS_C_ES.verify ~ WOTS_TW_ES_NPRF.verify :
          ={pk} /\ pk{2}.`3 = witness /\ sig{2} = sigc{1}.`1
          /\ m{2} = ThC pk{2}.`2 witness m{1} sigc{1}.`2
          ==> res{1} => res{2}].
proof.
  move=> encb; proc.
  inline{2} WOTS_TW_ES_NPRF.pkWOTS_from_sigWOTS.
  wp.
  while (pkWOTS_l{1} = pkWOTS0{2} /\ ps{1} = ps0{2} /\ ad{1} = ad0{2}
         /\ em{1} = em{2} /\ sig{1} = sig0{2}).
  + auto => />; smt().
  auto => />; smt().
qed.

(* R.choose commits the digest UNIFORMLY at the grind seed: sd = grindC (op),
   and the returned message = ThC ps witness mm (grindC ps witness mm) — the SAME
   digest the honest WOTS+C signer uses, on EVERY path (found or grind-fail).  The
   operational grind is the SAME invariant as `GrindSearch_run_computes_grind`
   (now proved), instantiated for R's loop (which reads the digest via OC). *)
lemma Rchoose_grind
  (A <: Adv_EUFNACMA_WOTSC{-R_WOTSTW_WOTSC, -STCRC_WC.Col.O_THFC_Default}) (s : pseed) :
  hoare[R_WOTSTW_WOTSC(A, STCRC_WC.Col.O_THFC_Default).choose :
          STCRC_WC.Col.O_THFC_Default.pp = s
          ==> R_WOTSTW_WOTSC.sd = grindC s witness R_WOTSTW_WOTSC.mm
              /\ res = ThC s witness R_WOTSTW_WOTSC.mm
                         (grindC s witness R_WOTSTW_WOTSC.mm)].
proof.
  proc.
  inline STCRC_WC.Col.O_THFC_Default.query.
  wp.
  while (   STCRC_WC.Col.O_THFC_Default.pp = s
         /\ (found => R_WOTSTW_WOTSC.sd = grindC s witness R_WOTSTW_WOTSC.mm)
         /\ (!found => R_WOTSTW_WOTSC.sd = witness)
         /\ (!found =>
               head witness
                 (filter (fun c => predC (ThC s witness R_WOTSTW_WOTSC.mm c)) cs)
               = grindC s witness R_WOTSTW_WOTSC.mm)).
  + auto => /> *; smt(STCRC_WC.G.head_filter_ne).
  wp.
  call (: STCRC_WC.Col.O_THFC_Default.pp = s).
  + by proc; auto.
  skip => /> *; smt(grindC_filter).
qed.

(* Thm C.2 second game-hop: GAME.1 <= WOTS-TW EU-naCMA via R_WOTSTW_WOTSC.
   Reduction correctness (paper Alg 10 / the d*≠d case) — PROVED (zero admit)
   under the single encode-bridge hypothesis. *)
lemma WOTSC_C2_hop2 (A <: Adv_EUFNACMA_WOTSC{-R_WOTSTW_WOTSC, -STCRC_WC.Col.O_THFC_Default}) &m :
    (* encode bridge (faithful modeling fact): the +C encoding of (m,c) IS the
       standard WOTS-TW encoding of the +C digest ThC.  This is the DEFINITION of
       `encode_msgWOTS_C` (= base_w of Th+C).

       UPDATED 2026-08-25.  This annotation used to end "abstract here only because
       the whole reduction keeps `encode_msgWOTS` parametric (see WOTS_C_Real.ec §3)".
       `encode_msgWOTS_C` IS NO LONGER ABSTRACT: WOTS_C_Real.ec:403 gives it exactly
       this body, so the hypothesis below is now DERIVABLE, by
       WOTS_C_Real.ec::encode_msgWOTS_C_compat.  It is KEPT as a hypothesis here ON
       PURPOSE -- this reduction is stated without relying on the body, and
       discharging it would move a pinned statement, which is a design decision and
       not a comment fix.  The stated REASON still holds for `encode_msgWOTS` itself,
       which remains a free op (WOTS_TW_ES.ec:624). *)
    (forall (p : pseed) (a : adrs) (x : dgstblock) (c : cntr),
       encode_msgWOTS_C p a x c = encode_msgWOTS (ThC p a x c)) =>
    Pr[GAME1_WOTSC(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
  <= Pr[EUF_NACMA_WOTSTW(R_WOTSTW_WOTSC(A), STCRC_WC.Col.O_THFC_Default).main() @ &m : res].
proof.
  move=> encb.
  byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
  proc.
  inline{2} R_WOTSTW_WOTSC(A, STCRC_WC.Col.O_THFC_Default).choose.
  inline{2} R_WOTSTW_WOTSC(A, STCRC_WC.Col.O_THFC_Default).forge.
  inline{1} STCRC_WC.Col.O_THFC_Default.init.
  inline{2} STCRC_WC.Col.O_THFC_Default.init.
  inline{2} STCRC_WC.Col.O_THFC_Default.query.
  seq 4 4 : (={glob A, glob STCRC_WC.Col.O_THFC_Default} /\ ps{1} = ps{2}
             /\ STCRC_WC.Col.O_THFC_Default.pp{2} = ps{2}).
  + auto => />.
  exists* ps{2}; elim* => psv.
  seq 1 1 : (={glob A, glob STCRC_WC.Col.O_THFC_Default} /\ ps{1} = ps{2}
             /\ m{1} = R_WOTSTW_WOTSC.mm{2}
             /\ STCRC_WC.Col.O_THFC_Default.pp{2} = psv /\ psv = ps{2}).
  + call (: ={glob STCRC_WC.Col.O_THFC_Default} /\ STCRC_WC.Col.O_THFC_Default.pp{2} = psv).
    + by proc; auto.
    by auto.
  (* grind block (side2 only): sd = grindC, and the returned message is the
     honest +C digest ThC ps witness mm (grindC ps witness mm) — UNIFORMLY. *)
  seq 0 11 : (={glob A} /\ ps{1} = ps{2} /\ m{1} = R_WOTSTW_WOTSC.mm{2}
             /\ m{2} = ThC psv witness R_WOTSTW_WOTSC.mm{2}
                         (grindC psv witness R_WOTSTW_WOTSC.mm{2})
             /\ psv = ps{2}
             /\ R_WOTSTW_WOTSC.sd{2} = grindC psv witness R_WOTSTW_WOTSC.mm{2}).
  + wp.
    while{2} (   STCRC_WC.Col.O_THFC_Default.pp{2} = psv
              /\ (found{2} => R_WOTSTW_WOTSC.sd{2} = grindC psv witness R_WOTSTW_WOTSC.mm{2})
              /\ (!found{2} => R_WOTSTW_WOTSC.sd{2} = witness)
              /\ (!found{2} =>
                    head witness
                      (filter (fun c => predC (ThC psv witness R_WOTSTW_WOTSC.mm{2} c)) cs{2})
                    = grindC psv witness R_WOTSTW_WOTSC.mm{2}))
             (size cs{2}).
    + move=> &n z; wp; skip => /> &hr *.
      have hfn := STCRC_WC.G.head_filter_ne
        (fun (c : cntr) => predC (ThC psv witness R_WOTSTW_WOTSC.mm{hr} c)) cs{hr}.
      smt(size_behead size_ge0 size_eq0).
    auto => /> *; smt(grindC_filter size_ge0 size_eq0).
  (* keygen: keypairs identical, sk/pk carry (psv, witness). *)
  seq 1 1 : (={glob A, pk, sk} /\ ps{1} = ps{2} /\ m{1} = R_WOTSTW_WOTSC.mm{2}
             /\ m{2} = ThC psv witness R_WOTSTW_WOTSC.mm{2}
                         (grindC psv witness R_WOTSTW_WOTSC.mm{2})
             /\ psv = ps{2} /\ sk{2}.`2 = psv /\ sk{2}.`3 = witness
             /\ pk{2}.`2 = psv /\ pk{2}.`3 = witness
             /\ R_WOTSTW_WOTSC.sd{2} = grindC psv witness R_WOTSTW_WOTSC.mm{2}).
  + call (keygenC_TW_s psv witness); skip => />.
  (* sign: signatures identical, WOTS+C counter = grindC = sd. *)
  seq 1 1 : (={glob A, pk} /\ ps{1} = ps{2} /\ m{1} = R_WOTSTW_WOTSC.mm{2}
             /\ psv = ps{2} /\ pk{2}.`2 = psv /\ pk{2}.`3 = witness
             /\ m{2} = ThC psv witness R_WOTSTW_WOTSC.mm{2}
                         (grindC psv witness R_WOTSTW_WOTSC.mm{2})
             /\ sigc{1} = (sig{2}, R_WOTSTW_WOTSC.sd{2})
             /\ sigc{1}.`2 = grindC psv witness R_WOTSTW_WOTSC.mm{2}).
  + exists* R_WOTSTW_WOTSC.mm{2}; elim* => mmv.
    call (signC_TW psv witness mmv encb); skip => /> *; smt().
  (* forge (A, no oracle: same input `(sig, grindC)` => same output), then the
     R.forge digest binding, then verifyC_TW2, then the post: GAME.1's
     non-collision IS the WOTS-TW freshness `digest' <> d`.  No p_nu term. *)
  (* forge/verify/post TAIL.  verifyC_TW2 transfers validity from the WOTS+C
     forgery to the WOTS-TW forgery on the +C digest; the oracle-free forge is
     coupled by `call (: true)` (A touches no oracle, so same (glob A, arg) gives
     same res); the post is exactly GAME.1's non-collision
     `ThC ps witness mm grindC <> ThC ps witness m' c'`, which IS the WOTS-TW
     freshness `digest' <> d` after the forge result aligns.  No p_nu term. *)
  call (verifyC_TW2 encb).
  wp; sp.
  call (: true).
  skip => /> *; smt().
qed.

(* ==========================================================================
   THEOREM C.2 (single-instance WOTS+C EU-naCMA), paper 2022/778 App C.
   PROVED (fully zero-admit) by composing the two game-hops (linear real
   arithmetic).  Both game-hop bounds (WOTSC_C2_hop1 via the S-TCR(+C)
   reduction, WOTSC_C2_hop2 via the WOTS-TW reduction) are now machine-checked
   with real reduction bodies, under the three explicit hypotheses
   `1 <= p_tgts`, address-separation (`sep`), and the encode bridge (`encb`).
   ========================================================================== *)
lemma EUFNACMA_WOTSC_C2
  (A <: Adv_EUFNACMA_WOTSC{-R_STCRC_WOTSC, -R_WOTSTW_WOTSC, -G0_inst,
                           -STCRC_WC.O_STCRC_Default, -STCRC_WC.Col.O_THFC_Default}) &m :
    1 <= p_tgts =>
    hoare[A(STCRC_WC.Col.O_THFC_Default).choose :
            STCRC_WC.Col.O_THFC_Default.tws = []
            ==> ! (witness \in STCRC_WC.Col.O_THFC_Default.tws)] =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (c : cntr),
       encode_msgWOTS_C p a x c = encode_msgWOTS (ThC p a x c)) =>
    Pr[EUF_NACMA_WOTSC(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
  <=   Pr[STCRC_WC.S_TCR_C(R_STCRC_WOTSC(A),
                           STCRC_WC.O_STCRC_Default,
                           STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
     + Pr[EUF_NACMA_WOTSTW(R_WOTSTW_WOTSC(A),
                           STCRC_WC.Col.O_THFC_Default).main() @ &m : res].
proof.
  move=> le1_ptgts sep encb.
  have h1 := WOTSC_C2_hop1 A &m le1_ptgts sep.
  have h2 := WOTSC_C2_hop2 A &m encb.
  smt().
qed.
