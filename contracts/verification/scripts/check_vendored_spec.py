#!/usr/bin/env python3
"""§33 P1 — verify the vendored copies in extracted/Extracted/ faithfully
transcribe their SphincsCVerify v4.22 sources:

  * SpecVendored.lean    — ByteVec/Adrs definitions from Spec/{Bytes,Adrs}.lean
  * ForsSpecVendored.lean — digest-field decoders from Spec/{Bytes,Params} + Util/Bits
  * Sha256Vendored.lean  — FIPS 180-4 SHA-256 from Spec/Sha256Impl.lean

The version bridge's trust rests on the vendored copies being verbatim; this
catches drift if either side is edited."""
import re, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]

# (source files, vendored copy, definitions whose BODIES must match
#  byte-for-byte — semantic content; markers are matched against the start
#  of a stripped line, so include any attribute prefix like `@[inline] `)
CHECKS = [
    ([ROOT/"lean/SphincsCVerify/Spec/Bytes.lean",
      ROOT/"lean/SphincsCVerify/Spec/Params.lean",
      ROOT/"lean/SphincsCVerify/Spec/Adrs.lean",
      ROOT/"lean/SphincsCVerify/Spec/Hash.lean",
      ROOT/"lean/SphincsCVerify/Spec/Wots.lean"],
     ROOT/"extracted/Extracted/WotsRecoveryVendored.lean",
     ["def take ", "def pad16 ", "def truncate16 ", "def W :", "def TargetSum :",
      "def ADRS_WOTS :", "def ADRS_WOTS_PK :", "def setChainPos ", "def wots ",
      "def wotsPk ", "def th (", "def thMulti ", "def chainHash\n",
      "structure Sigma", "def pkFromSig\n"]),
    ([ROOT/"lean/SphincsCVerify/Spec/Bytes.lean",
      ROOT/"lean/SphincsCVerify/Spec/Params.lean",
      ROOT/"lean/SphincsCVerify/Spec/Hash.lean",
      ROOT/"lean/SphincsCVerify/Util/Bits.lean"],
     ROOT/"extracted/Extracted/WotsSpecVendored.lean",
     ["def zero ", "def u32ToB32 ", "def LogW :", "def L :",
      "def wotsDigest\n", "def extractDigits ", "def digitSum "]),
    ([ROOT/"lean/SphincsCVerify/Spec/Bytes.lean",
      ROOT/"lean/SphincsCVerify/Spec/Hash.lean"],
     ROOT/"extracted/Extracted/HMsgSpecVendored.lean",
     ["def ones ", "structure ByteSeg", "def ofByteVec ",
      "def ByteSeg.flatten ", "def sha256_impl ",
      "@[irreducible] def sha256 :", "def hMsg\n"]),
    ([ROOT/"lean/SphincsCVerify/Spec/Bytes.lean",
      ROOT/"lean/SphincsCVerify/Spec/Params.lean",
      ROOT/"lean/SphincsCVerify/Util/Bits.lean"],
     ROOT/"extracted/Extracted/ForsSpecVendored.lean",
     ["def get ", "def H :", "def K :", "def A :",
      "@[inline] def readBitsLe.stepValue", "def readBitsLe ",
      "def extractForsIndices ", "def extractHtIndex "]),
    ([ROOT/"lean/SphincsCVerify/Spec/Bytes.lean",
      ROOT/"lean/SphincsCVerify/Spec/Adrs.lean"],
     ROOT/"extracted/Extracted/SpecVendored.lean",
     # + ByteVec / cast / append / Adrs (2026-07-02, F5): the ADRS version bridge
     # `specMakeAdrs_eq_vendored` simp-unfolds ByteVec.cast + .append, so a drift in
     # them silently invalidates the bridge; they were vendored but UNCHECKED.
     ["structure ByteVec", "def cast", "def append", "def Adrs",
      "def ofU32BE", "def ofU64BE", "def make\n", "def setChainIndex"]),
    ([ROOT/"lean/SphincsCVerify/Spec/Sha256Impl.lean"],
     ROOT/"extracted/Extracted/Sha256Vendored.lean",
     ["abbrev Word", "def Rounds", "def DigestWords", "def BlockWords",
      "@[inline] def rotr", "@[inline] def ch", "@[inline] def maj",
      "@[inline] def bigSigma0", "@[inline] def bigSigma1",
      "@[inline] def smallSigma0", "@[inline] def smallSigma1",
      "def H0", "def K :", "def messageSchedule", "structure Working",
      "def Working.ofArray", "def Working.toArray", "def round ",
      "def runRounds", "def stateAdd", "def compress",
      "@[inline] def u8ToWord", "@[inline] def wordLowU8",
      "@[inline] def wordByteBE", "@[inline] def bytesToWordBE",
      "def bytesToWords", "def wordsToBytes", "def zeroPadCount",
      "def encodeBE64", "def zeroBytes", "def pad ", "def toBlocks",
      "def sha256Words", "def sha256Bytes"]),
]

def grab(text, marker):
    """Return the def's lines from `marker` until the next top-level def/end."""
    lines = text.split("\n")
    key = marker.rstrip("\n")
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith(key) and (marker.endswith("\n") and ln.strip()==key.strip() or not marker.endswith("\n") and key in ln):
            body=[ln]
            for nxt in lines[i+1:]:
                if re.match(r'^\s*(def |structure |theorem |instance |namespace |end |/-)', nxt) and nxt.strip():
                    break
                body.append(nxt)
            # strip comments + blank-trailing, normalize whitespace
            joined=' '.join(b.split('--')[0] for b in body)
            return re.sub(r'\s+',' ',joined).strip()
    return None

ok = True
for srcs, ven, defs in CHECKS:
    srctext = "\n".join(p.read_text() for p in srcs)
    ventext = ven.read_text()
    for d in defs:
        s, v = grab(srctext, d), grab(ventext, d)
        if s is None: print(f"[{ven.name}] MISSING in source: {d!r}"); ok=False; continue
        if v is None: print(f"[{ven.name}] MISSING in vendored: {d!r}"); ok=False; continue
        if s != v:
            print(f"[{ven.name}] DRIFT in {d!r}:\n  src: {s}\n  ven: {v}")
            ok=False
if ok: print("OK: vendored spec + digest decoders + SHA-256 are faithful copies of the SphincsCVerify source")
sys.exit(0 if ok else 1)
