-- Reuse the one-shot `sha256_bytes` boundary model (Hash/FunsExternal) and the
-- actual extracted `truncate` / `sha256_bytes16` bodies (Hash/Funs).
-- No new logical assumptions; concrete backend correctness remains separate.
import Extracted.Hash.Funs
