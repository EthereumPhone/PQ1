/- Generated independent functional tree examples. -/
import Extracted.C10Representation
import Aeneas
open C10Representation
set_option maxRecDepth 8192
set_option maxHeartbeats 2000000
namespace Extracted.C10FunctionalTreeFixtures
def toy (bs : List Int) : List Int := List.replicate 32 ((1 * (bs.getD 32 0) + 3 * (bs.getD 36 0) + 5 * (bs.getD 43 0) + 7 * (bs.getD 47 0) + 11 * (bs.getD 51 0) + 13 * (bs.getD 59 0) + 17 * (bs.getD 60 0) + 19 * (bs.getD 63 0) + 23 * (bs.getD 64 0) + 29 * (bs.getD 96 0)) % 256)
example : merkle_recover_value toy (List.replicate 32 0) 0 0 (List.replicate 16 3) 0 [(List.replicate 16 11), (List.replicate 16 18), (List.replicate 16 25), (List.replicate 16 32), (List.replicate 16 39), (List.replicate 16 46), (List.replicate 16 53), (List.replicate 16 60), (List.replicate 16 67)] = (List.replicate 16 127) := by decide
example : merkle_recover_value toy (List.replicate 32 0) 0 0 (List.replicate 16 3) 1 [(List.replicate 16 11), (List.replicate 16 18), (List.replicate 16 25), (List.replicate 16 32), (List.replicate 16 39), (List.replicate 16 46), (List.replicate 16 53), (List.replicate 16 60), (List.replicate 16 67)] = (List.replicate 16 79) := by decide
example : merkle_recover_value toy (List.replicate 32 0) 4294967295 18446744073709551615 (List.replicate 16 3) 4294967295 [(List.replicate 16 11), (List.replicate 16 18), (List.replicate 16 25), (List.replicate 16 32), (List.replicate 16 39), (List.replicate 16 46), (List.replicate 16 53), (List.replicate 16 60), (List.replicate 16 67)] = (List.replicate 16 158) := by decide
example : fors_recover_value toy (List.replicate 32 0) 0 0 0 (List.replicate 16 3) [(List.replicate 16 11), (List.replicate 16 18), (List.replicate 16 25), (List.replicate 16 32), (List.replicate 16 39), (List.replicate 16 46), (List.replicate 16 53), (List.replicate 16 60), (List.replicate 16 67), (List.replicate 16 74), (List.replicate 16 81)] = (List.replicate 16 151) := by decide
example : fors_recover_value toy (List.replicate 32 0) 0 0 1 (List.replicate 16 3) [(List.replicate 16 11), (List.replicate 16 18), (List.replicate 16 25), (List.replicate 16 32), (List.replicate 16 39), (List.replicate 16 46), (List.replicate 16 53), (List.replicate 16 60), (List.replicate 16 67), (List.replicate 16 74), (List.replicate 16 81)] = (List.replicate 16 232) := by decide
example : fors_recover_value toy (List.replicate 32 0) 1 12 2048 (List.replicate 16 3) [(List.replicate 16 11), (List.replicate 16 18), (List.replicate 16 25), (List.replicate 16 32), (List.replicate 16 39), (List.replicate 16 46), (List.replicate 16 53), (List.replicate 16 60), (List.replicate 16 67), (List.replicate 16 74), (List.replicate 16 81)] = (List.replicate 16 232) := by decide
example : fors_recover_value toy (List.replicate 32 0) 4294967295 4294967295 4294967295 (List.replicate 16 3) [(List.replicate 16 11), (List.replicate 16 18), (List.replicate 16 25), (List.replicate 16 32), (List.replicate 16 39), (List.replicate 16 46), (List.replicate 16 53), (List.replicate 16 60), (List.replicate 16 67), (List.replicate 16 74), (List.replicate 16 81)] = (List.replicate 16 151) := by decide
end Extracted.C10FunctionalTreeFixtures
