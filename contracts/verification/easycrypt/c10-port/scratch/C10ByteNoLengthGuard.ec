require import AllCore List RawSignature RawDecode.
lemma discarded_length_guard bs : signature_width (decode_signature bs).
proof. exact (decoded_signature_width bs). qed.
