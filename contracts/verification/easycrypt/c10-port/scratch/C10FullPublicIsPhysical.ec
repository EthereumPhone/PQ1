require import AllCore FullPrefix.
lemma public_calls_include_private_calls : full_physical_budget 0 0 = full_public_budget 0 0.
proof. rewrite /full_physical_budget /full_public_budget /=; by trivial. qed.
