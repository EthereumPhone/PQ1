require import AllCore List BitEncoding C10RawOracle C10Bytes RawKeygen RawCodec.
lemma discarded_value_guard bs : size bs = 4 => be 4 (BS2Int.bs2int (bytes_to_bits bs)) = bs.
proof. exact (count_bytes_roundtrip bs). qed.
