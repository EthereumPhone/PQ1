-- Two full trees selected from eight independently checked Rust cases.
namespace XmssRootDiff
structure Vector where
  seed : Array UInt8
  sk : Array UInt8
  layer : Nat
  tree : Nat
  lo : Nat
  hi : Nat
  publicRoot : Bool
  result : Array UInt8
  deriving Inhabited
def vectors : List Vector := [
{ seed := #[13, 20, 27, 34, 41, 48, 55, 62, 69, 76, 83, 90, 97, 104, 111, 118, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], sk := #[11, 34, 57, 80, 103, 126, 149, 172, 195, 218, 241, 8, 31, 54, 77, 100, 123, 146, 169, 192, 215, 238, 5, 28, 51, 74, 97, 120, 143, 166, 189, 212], layer := 1, tree := 0, lo := 0, hi := 0, publicRoot := true, result := #[108, 14, 197, 177, 22, 95, 225, 215, 90, 62, 136, 74, 223, 226, 146, 62] },
{ seed := #[13, 20, 27, 34, 41, 48, 55, 62, 69, 76, 83, 90, 97, 104, 111, 118, 125, 132, 139, 146, 153, 160, 167, 174, 181, 188, 195, 202, 209, 216, 223, 230], sk := #[11, 34, 57, 80, 103, 126, 149, 172, 195, 218, 241, 8, 31, 54, 77, 100, 123, 146, 169, 192, 215, 238, 5, 28, 51, 74, 97, 120, 143, 166, 189, 212], layer := 2164392708, tree := 9305357566071262703, lo := 0, hi := 255, publicRoot := false, result := #[87, 195, 206, 207, 0, 83, 193, 226, 61, 140, 186, 202, 193, 0, 90, 13] },
]
end XmssRootDiff
