require import AllCore List FMap C10RawOracle TargetTableProjection.
lemma absent_entry_selected (target : raw_input) (value : digest) :
 selected_table target value empty empty.
proof. rewrite /selected_table /=; by trivial. qed.
