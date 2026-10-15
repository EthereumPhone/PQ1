require import AllCore List StdOrder.
require import RestrictedGrowthWords ReverseGrowthEncoding.

lemma twelve_two : stirling 12 2=2047.
proof.
  have h0_m : stirling 0 (-1)=0.
  + apply stirling_outside; smt().
  have h0_0 : stirling 0 (0)=1.
  + by rewrite stirling_zero.
  have h0_1 : stirling 0 (1)=0.
  + apply stirling_outside; smt().
  have h0_2 : stirling 0 (2)=0.
  + apply stirling_outside; smt().
  have h1_m : stirling 1 (-1)=0.
  + apply stirling_outside; smt().
  have h1_0 : stirling 1 (0)=0.
  + have hr:=stirling_recurrence 0 0 _; first smt().
    smt().
  have h1_1 : stirling 1 (1)=1.
  + have hr:=stirling_recurrence 0 1 _; first smt().
    smt().
  have h1_2 : stirling 1 (2)=0.
  + apply stirling_outside; smt().
  have h2_m : stirling 2 (-1)=0.
  + apply stirling_outside; smt().
  have h2_0 : stirling 2 (0)=0.
  + have hr:=stirling_recurrence 1 0 _; first smt().
    smt().
  have h2_1 : stirling 2 (1)=1.
  + have hr:=stirling_recurrence 1 1 _; first smt().
    smt().
  have h2_2 : stirling 2 (2)=1.
  + have hr:=stirling_recurrence 1 2 _; first smt().
    smt().
  have h3_m : stirling 3 (-1)=0.
  + apply stirling_outside; smt().
  have h3_0 : stirling 3 (0)=0.
  + have hr:=stirling_recurrence 2 0 _; first smt().
    smt().
  have h3_1 : stirling 3 (1)=1.
  + have hr:=stirling_recurrence 2 1 _; first smt().
    smt().
  have h3_2 : stirling 3 (2)=3.
  + have hr:=stirling_recurrence 2 2 _; first smt().
    smt().
  have h4_m : stirling 4 (-1)=0.
  + apply stirling_outside; smt().
  have h4_0 : stirling 4 (0)=0.
  + have hr:=stirling_recurrence 3 0 _; first smt().
    smt().
  have h4_1 : stirling 4 (1)=1.
  + have hr:=stirling_recurrence 3 1 _; first smt().
    smt().
  have h4_2 : stirling 4 (2)=7.
  + have hr:=stirling_recurrence 3 2 _; first smt().
    smt().
  have h5_m : stirling 5 (-1)=0.
  + apply stirling_outside; smt().
  have h5_0 : stirling 5 (0)=0.
  + have hr:=stirling_recurrence 4 0 _; first smt().
    smt().
  have h5_1 : stirling 5 (1)=1.
  + have hr:=stirling_recurrence 4 1 _; first smt().
    smt().
  have h5_2 : stirling 5 (2)=15.
  + have hr:=stirling_recurrence 4 2 _; first smt().
    smt().
  have h6_m : stirling 6 (-1)=0.
  + apply stirling_outside; smt().
  have h6_0 : stirling 6 (0)=0.
  + have hr:=stirling_recurrence 5 0 _; first smt().
    smt().
  have h6_1 : stirling 6 (1)=1.
  + have hr:=stirling_recurrence 5 1 _; first smt().
    smt().
  have h6_2 : stirling 6 (2)=31.
  + have hr:=stirling_recurrence 5 2 _; first smt().
    smt().
  have h7_m : stirling 7 (-1)=0.
  + apply stirling_outside; smt().
  have h7_0 : stirling 7 (0)=0.
  + have hr:=stirling_recurrence 6 0 _; first smt().
    smt().
  have h7_1 : stirling 7 (1)=1.
  + have hr:=stirling_recurrence 6 1 _; first smt().
    smt().
  have h7_2 : stirling 7 (2)=63.
  + have hr:=stirling_recurrence 6 2 _; first smt().
    smt().
  have h8_m : stirling 8 (-1)=0.
  + apply stirling_outside; smt().
  have h8_0 : stirling 8 (0)=0.
  + have hr:=stirling_recurrence 7 0 _; first smt().
    smt().
  have h8_1 : stirling 8 (1)=1.
  + have hr:=stirling_recurrence 7 1 _; first smt().
    smt().
  have h8_2 : stirling 8 (2)=127.
  + have hr:=stirling_recurrence 7 2 _; first smt().
    smt().
  have h9_m : stirling 9 (-1)=0.
  + apply stirling_outside; smt().
  have h9_0 : stirling 9 (0)=0.
  + have hr:=stirling_recurrence 8 0 _; first smt().
    smt().
  have h9_1 : stirling 9 (1)=1.
  + have hr:=stirling_recurrence 8 1 _; first smt().
    smt().
  have h9_2 : stirling 9 (2)=255.
  + have hr:=stirling_recurrence 8 2 _; first smt().
    smt().
  have h10_m : stirling 10 (-1)=0.
  + apply stirling_outside; smt().
  have h10_0 : stirling 10 (0)=0.
  + have hr:=stirling_recurrence 9 0 _; first smt().
    smt().
  have h10_1 : stirling 10 (1)=1.
  + have hr:=stirling_recurrence 9 1 _; first smt().
    smt().
  have h10_2 : stirling 10 (2)=511.
  + have hr:=stirling_recurrence 9 2 _; first smt().
    smt().
  have h11_m : stirling 11 (-1)=0.
  + apply stirling_outside; smt().
  have h11_0 : stirling 11 (0)=0.
  + have hr:=stirling_recurrence 10 0 _; first smt().
    smt().
  have h11_1 : stirling 11 (1)=1.
  + have hr:=stirling_recurrence 10 1 _; first smt().
    smt().
  have h11_2 : stirling 11 (2)=1023.
  + have hr:=stirling_recurrence 10 2 _; first smt().
    smt().
  have h12_m : stirling 12 (-1)=0.
  + apply stirling_outside; smt().
  have h12_0 : stirling 12 (0)=0.
  + have hr:=stirling_recurrence 11 0 _; first smt().
    smt().
  have h12_1 : stirling 12 (1)=1.
  + have hr:=stirling_recurrence 11 1 _; first smt().
    smt().
  have h12_2 : stirling 12 (2)=2047.
  + have hr:=stirling_recurrence 11 2 _; first smt().
    smt().
  exact h12_2.
qed.

lemma checked : size (exact_growth_words 12 2)=2048.
proof.
  have h : size (exact_growth_words 12 2)=2047.
  + rewrite exact_growth_words_size 1:/#; exact twelve_two.
  exact h.
qed.
