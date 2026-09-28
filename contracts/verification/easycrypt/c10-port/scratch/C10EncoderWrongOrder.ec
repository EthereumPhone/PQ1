require import AllCore List BitEncoding.
require import SPHINCS_PLUS C10Encoding RadixEncoding C10DigitUniform.
import FSSLXMTWES FSSLXMTWES.WTWES EmsgWOTS.
op marker : msgWOTS = MDigestBlock.insubd (mkseq (fun j => j = 128) 256).
lemma bit128 : BaseW.val (encode_msgWOTS marker).[42] = 0.
proof.
  rewrite deployed_digit 1:// /marker MDigestBlock.insubdK.
  + by rewrite size_mkseq /n_m n_val.
  by rewrite digit3 !nth_mkseq 1..3:// /= /b2i.
qed.
