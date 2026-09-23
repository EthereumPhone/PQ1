require import AllCore.

lemma stack_pow2_9 : 2 ^ 9 = 512.
proof.
by rewrite (_ : 9 = 8 + 1) 1:// exprS 1://
           (_ : 8 = 7 + 1) 1:// exprS 1://
           (_ : 7 = 6 + 1) 1:// exprS 1://
           (_ : 6 = 5 + 1) 1:// exprS 1://
           (_ : 5 = 4 + 1) 1:// exprS 1://
           (_ : 4 = 3 + 1) 1:// exprS 1://
           (_ : 3 = 2 + 1) 1:// exprS 1://
           (_ : 2 = 1 + 1) 1:// exprS 1:// expr1.
qed.

lemma stack_pow2_11 : 2 ^ 11 = 2048.
proof.
  by rewrite (_ : 11 = 10+1) 1:// exprS 1://
             (_ : 10 = 9+1) 1:// exprS 1:// stack_pow2_9.
qed.
