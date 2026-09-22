require import AllCore List.
require import C10Bytes C10Counter C10DeployedInstance.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
require import C10HashDomains.

lemma checked_hmsg_width (seed root r message : int list) :
  size seed = 32 => size root = 32 => size r = 32 => size message = 32 =>
  size (hmsg_input seed root r message) = 160.
proof. exact hmsg_width. qed.

lemma checked_r_hmsg_separate (secret random message seed root r : int list) (nonce : counter) :
  size secret = 32 => size message = 32 => size random = 0 \/ size random = 16 =>
  size seed = 32 => size root = 32 => size r = 32 =>
  r_input secret random message nonce <> hmsg_input seed root r message.
proof. exact r_hmsg_separate. qed.

lemma checked_tagged_inputs_separate (seed1 seed2 address1 address2 payload1 payload2 : int list) :
  size seed1 = 32 => size seed2 = 32 => size address1 = 32 => size address2 = 32 =>
  address_tag address1 <> address_tag address2 =>
  seed1 ++ address1 ++ payload1 <> seed2 ++ address2 ++ payload2.
proof. exact tagged_inputs_separate. qed.
