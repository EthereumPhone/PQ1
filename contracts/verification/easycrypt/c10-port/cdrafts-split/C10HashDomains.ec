(* Manual byte layouts of hash.rs/fors.rs. The length and address-tag lemmas
   justify domain separation for these call shapes, not a SHA-256 idealization
   or a simulation of all collection-oracle calls. *)
require import AllCore List.
require import C10Bytes C10Counter C10DeployedInstance.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.

op hmsg_input (seed root r message : int list) =
  seed ++ root ++ r ++ message ++ nseq 32 255.

op r_input (secret random message : int list) (nonce : counter) =
  secret ++ [82;95;103;114;105;110;100] ++ random ++ message ++
    nseq 28 0 ++ counter_bytes nonce.

op pair_input (seed address lhs rhs : int list) =
  seed ++ address ++ lhs ++ rhs.

lemma hmsg_width (seed root r message : int list) :
  size seed = 32 => size root = 32 => size r = 32 => size message = 32 =>
  size (hmsg_input seed root r message) = 160.
proof. by move=> hs hr hR hm; rewrite /hmsg_input !size_cat !size_nseq hs hr hR hm. qed.

lemma r_width (secret random message : int list) (nonce : counter) :
  size secret = 32 => size message = 32 =>
  size (r_input secret random message nonce) = 103 + size random.
proof.
  by move=> hs hm; rewrite /r_input !size_cat !size_nseq counter_bytes_size hs hm /=; ring.
qed.

lemma pair_width (seed address lhs rhs : int list) :
  size seed = 32 => size address = 32 => size lhs = 32 => size rhs = 32 =>
  size (pair_input seed address lhs rhs) = 128.
proof. by move=> hs ha hl hr; rewrite /pair_input !size_cat hs ha hl hr. qed.

(* For fixed seed/root/message, the H_msg preimage repeats exactly when the
   padded R repeats. A distinct R-derivation nonce does not prove otherwise. *)
lemma hmsg_r_injective (seed root message r1 r2 : int list) :
  hmsg_input seed root r1 message = hmsg_input seed root r2 message <=> r1 = r2.
proof.
  split; last by move=> ->.
  rewrite /hmsg_input => he.
  exact (catsI (seed ++ root) _ _
    (catIs _ _ message (catIs _ _ (nseq 32 255) he))).
qed.

lemma r_hmsg_separate (secret random message seed root r : int list) (nonce : counter) :
  size secret = 32 => size message = 32 => size random = 0 \/ size random = 16 =>
  size seed = 32 => size root = 32 => size r = 32 =>
  r_input secret random message nonce <> hmsg_input seed root r message.
proof.
  move=> hs hm hr hseed hroot hR.
  have h1 := r_width secret random message nonce hs hm.
  have h2 := hmsg_width seed root r message hseed hroot hR hm.
  smt().
qed.

lemma hmsg_wots_separate (seed root r message address : int list)
  (m : dgstblock) (nonce : counter) :
  size seed = 32 => size root = 32 => size r = 32 => size message = 32 =>
  size address = 32 =>
  hmsg_input seed root r message <> seed ++ address ++ c10_payload (m,nonce).
proof.
  move=> hs hr hR hm ha.
  have h1 := hmsg_width seed root r message hs hr hR hm.
  have h2 : size (seed ++ address ++ c10_payload (m,nonce)) = 128
    by rewrite (size_cat (seed ++ address) (c10_payload (m,nonce)))
      (size_cat seed address) hs ha c10_payload_width.
  smt().
qed.

op address_tag (address : int list) = take 4 (drop 12 address).

lemma input_address (seed address payload : int list) :
  size seed = 32 => size address = 32 =>
  take 32 (drop 32 (seed ++ address ++ payload)) = address.
proof.
  by move=> hs ha; rewrite -!catA drop_cat hs /= drop0 take_cat ha /= take0 cats0.
qed.

(* WOTS digest and pair hashing share the 128-byte length. Their actual ADRS
   type fields must differ (WOTS=0; Merkle tree=2 or FORS tree=3). *)
lemma tagged_inputs_separate (seed1 seed2 address1 address2 payload1 payload2 : int list) :
  size seed1 = 32 => size seed2 = 32 => size address1 = 32 => size address2 = 32 =>
  address_tag address1 <> address_tag address2 =>
  seed1 ++ address1 ++ payload1 <> seed2 ++ address2 ++ payload2.
proof.
  move=> hs1 hs2 ha1 ha2 htags; apply negP => he.
  have ha : address1 = address2.
  + by rewrite -(input_address seed1 address1 payload1 hs1 ha1)
      -(input_address seed2 address2 payload2 hs2 ha2) he.
  by move: htags; rewrite ha.
qed.
