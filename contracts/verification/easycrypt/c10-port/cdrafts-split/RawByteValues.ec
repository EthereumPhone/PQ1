(* Node truncation always yields bytes, including totalized off-support inputs. *)
require import AllCore List IntDiv BitEncoding.
require import C10RawOracle C10RawGrind C10Bytes RawKeygen RawLayer RawSigner RawSignature RawWidths ByteSession ShuffleBytes.

op byte_rows (rows : raw_input list) = all byte_values rows.
op byte_stack (stack : (raw_input * int) list) = all (fun (e : raw_input * int) => byte_values e.`1) stack.
op layer_bytes (sig : layer_signature) = byte_rows sig.`1 /\ byte_rows sig.`3.
op signature_bytes (sig : raw_signature) =
  byte_values sig.`1 /\ byte_rows sig.`2 /\ all byte_rows sig.`3 /\ all layer_bytes sig.`4.

lemma zero_bytes n : byte_values (nseq n 0).
proof. rewrite /byte_values all_nseq; smt(). qed.
lemma node_bytes d : byte_values (node d).
proof.
  rewrite /byte_values /node; apply/allP => b hb.
  have hc : all (fun b => 0<=b<256) (compact_r d) by rewrite /compact_r; exact (shuffle_bytes_valid _).
  smt(mem_take mem_cat allP mem_nseq).
qed.
lemma compact_bytes d : byte_values (compact_r d).
proof. rewrite /byte_values /compact_r; apply shuffle_bytes_valid. qed.

lemma byte_rows_put rows i x : byte_rows rows => byte_values x => byte_rows (put rows i x).
proof. rewrite /byte_rows; exact (all_put_preserved byte_values rows i x). qed.
lemma byte_rows_zeros n : byte_rows (nseq n (nseq 16 0)).
proof. rewrite /byte_rows all_nseq; smt(zero_bytes). qed.
lemma byte_stack_tail stack : byte_stack stack => byte_stack (behead stack).
proof. case stack => // x xs; rewrite /byte_stack /=; smt(). qed.
lemma byte_stack_first stack : byte_stack stack => stack<>[] => byte_values (head ([],0) stack).`1.
proof. case stack => // x xs; rewrite /byte_stack /=; smt(). qed.
lemma byte_stack_head stack : byte_stack stack => byte_values (head (nseq 16 0,0) stack).`1.
proof. case stack => //=; first smt(zero_bytes). move=> x xs; rewrite /byte_stack /=; smt(). qed.
