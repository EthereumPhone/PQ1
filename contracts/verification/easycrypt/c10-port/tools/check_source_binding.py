#!/usr/bin/env python3
"""Fail on drift in the manually reviewed EasyCrypt/Rust correspondence.

Hashes pin the inputs to that review; they do not establish refinement. Model
proofs and the real-helper host test supply separate, explicitly scoped evidence.
"""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.joinpath('../../../../..').resolve()
PORT = 'contracts/verification/easycrypt/c10-port/'
SOURCES = (
    'sphincs-c10/src/wots.rs', 'sphincs-c10/src/hash.rs', 'sphincs-c10/src/lib.rs',
    'sphincs-c10/src/fors.rs', 'sphincs-c10/src/address.rs', 'sphincs-c10/src/params.rs',
    'sphincs-c10/tests/easycrypt_transcript.rs',
    PORT + 'tools/check_source_binding.py',
    'contracts/verification/scripts/run_easycrypt_split.py',
    PORT + 'base-c10-split/WOTS_TW_ES.ec',
    PORT + 'base-c10-split/RadixEncoding.ec',
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'C10Counter', 'C10Bytes', 'C10BoundedGrind', 'C10DeployedInstance', 'WOTS_C_Real',
        'C10Encoding', 'C10DigitUniform', 'C10BoundedSigning', 'BoundedIID', 'C10BoundedIID',
        'C10BoundedGame', 'C10BoundedReduction', 'C10BoundedMA',
        'C10BoundedHypertree', 'C10BoundedLeaf',
        'FORS_C10', 'C10HypertreeCoverage', 'SharedROBounded', 'C10Randomizer',
        'C10HashDomains', 'C10SharedSearch', 'C10SearchBounds', 'C10HypertreeCharged',
        'XmssmtCC_All', 'C10WOTSCorrect', 'C10HypertreeCorrect', 'C10CubeCorrect',
        'C10CubeConstruction', 'C10ReductionChoose', 'C10ReductionForge',
        'C10AcceptedReduction', 'C10HypertreeAccepted', 'C10StatefulSearch',
        'C10RawOracle', 'C10RawGrind', 'FORSC10Digest')),
    'sphincs-c10/src/shuffle.rs',
    'sphincs-c10/src/hypertree.rs', 'sphincs-c10/src/merkle.rs',
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'AcceptedContexts', 'ByteBound', 'ByteSession', 'ContextExhaustion',
        'ExhaustionCharges', 'FullFailure', 'FullPrefix', 'FullSession', 'FullSessionCost',
        'GrindExhaustion', 'GrindReplay', 'GrindTail', 'GrindWitness',
        'IdealWitness', 'KeygenExhaustion', 'KeygenPrefixes', 'PersistentGrind',
        'PhysicalKeygenCost', 'PrefixBound', 'PrefixGames', 'PrefixGuess',
        'PrefixHybrid', 'PrefixIdeal', 'PrefixState', 'PreparedExhaustion',
        'PreparedGrind', 'PreparedHistory', 'PreparedRaw', 'RHistoryOps',
        'RSession', 'RSessionBound', 'RSessionCost', 'RSessionHistory',
        'RTailContexts', 'RTailFresh', 'RTailMessages', 'RawCodec',
        'RawCompositeWidths', 'RawDecode', 'RawForest', 'RawForestCost',
        'RawFors', 'RawForsCost', 'RawKeygen', 'RawKeygenCost',
        'RawLayer', 'RawLayerCost', 'RawMerkle', 'RawMerkleCost',
        'RawRHistory', 'RawSession', 'RawSessionBound', 'RawSessionCost',
        'RawShuffle', 'RawSignature', 'RawSigner', 'RawSignerCost',
        'RawSignerWidths', 'RawSlices', 'RawTreeWidths', 'RawTrial',
        'RawWidths', 'RawWots', 'RawWotsCost', 'RoleGrind',
        'RoleGrindCost', 'SecretPrefix', 'SessionClosedForm', 'SessionKeygen',
        'SessionPhysical', 'StreamBound', 'StreamExpectation', 'TrialExpectation',
    )),
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'AcceptedCoverage', 'AcceptedHypertree', 'AcceptedSampling', 'AuditComplete',
        'AuditPrefix', 'ByteAudit', 'ByteReplay', 'DigestCoordinates',
        'DigestPair', 'DigestPrefix', 'DigestWindow', 'FreshCoverage',
        'GrindHypertree', 'GrindJointCoverage', 'GrindReturned', 'PrefixAudit',
        'RawHistoryPreservation', 'SignerAccepted', 'SignerReturned', 'StreamAccepted',
        'TrialAccepted',
    )),
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'ByteHistory', 'ClassifiedBound', 'ClassifiedGrind', 'ClassifiedHistory',
        'ClassifiedSession', 'ClassifiedSigner', 'FullHistory', 'FullMessageHistory',
        'GrindTrace', 'GrindTraceRecorded', 'GrindTraceReplay', 'MessageHistory',
        'MonotoneHistory', 'PreparedFinish', 'SessionDigest', 'SignerMessages',
        'SignerRecorded', 'SignerTrace', 'VerifierHistory',
    )),
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'ForsLeafInputs', 'PathCollision', 'PathInputs', 'PathOracle',
        'PathReplay', 'RawForsComparison', 'RawForsPathReplay', 'RawPathComparison',
        'RawPathReplay', 'RecoveryHistory',
    )),
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'AuthAdvance', 'AuthCaptureIndex', 'AuthCaptureSchedule', 'AuthCaptureValue',
        'AuthPhase', 'AuthSlots', 'AuthStepInvariant', 'AuthSteps',
        'BuildRootProjection', 'BuilderPath', 'BuilderTotality', 'CatalogForest',
        'CatalogForestMerge', 'CatalogMerge', 'CatalogOracle', 'CatalogPath',
        'CatalogStack', 'CatalogWidths', 'DyadicStack', 'ForsBuildWitness',
        'ForsBuilderPath', 'ForsCatalogAuth', 'ForsCatalogObserver', 'ForsCatalogSound',
        'MerkleBuildWitness', 'MerkleBuilderPath', 'MerkleCatalogAuth', 'MerkleCatalogObserver',
        'MerkleCatalogSound', 'NodeCatalog', 'NodeCatalogDomain', 'NodeGridIndex',
        'NodeGridPath', 'RawBuilderReference', 'StackAlignment', 'StackPowers',
        'StackProjection', 'TotalBuilderReference', 'ForsBuilderComparison', 'ForsBuilderSecret',
        'ForsLeafOrigins', 'LeafOriginOracle', 'LeafOrigins', 'MerkleBuilderComparison',
        'ForsBuilderPrivate', 'ForsKnownSecret', 'ForsPrivateEntry', 'ForsPrivateLeaves',
        'ForsSignCorrect', 'ForsSignRecord', 'ForsSignWitness', 'SecretLeafOracle',
        'SecretLeafOrigins',
    )),
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'ActualWotsCorrect', 'ChainHistory', 'FixedChainReplay', 'FixedHashReplay',
        'FixedWotsChains', 'LinearChain', 'LinearOracle', 'LinearSplit',
        'PreparationHistory', 'RawChainReplay', 'RawChainTrace', 'RawCountRecorded',
        'RawLeafChains', 'RawShufflePermutation', 'RawWotsFill', 'RawWotsRecovery',
        'RawWotsReference', 'ShuffleBytes', 'ShuffleSwap', 'WotsChainReference',
        'WotsChainSplit', 'WotsCountWitness', 'WotsFillCorrect', 'WotsLeafReference',
        'WotsOpeningRecovery', 'WotsReference', 'WotsReferenceOracle', 'WotsReferenceRoot',
        'WotsReferenceStep', 'WotsSignCorrect', 'WotsSignWitness', 'WotsSignatureValue',
        'ActualForestCorrect', 'ForestOneStep', 'ForestOpenings', 'ForestOracle',
        'ForestRecoveryReplay', 'ForestSignRecorded', 'ForestWitness', 'ForsComponentHistory',
        'ForsOneRecorded', 'ForsOpening', 'ForsOpeningReplay', 'ActualLayerCorrect',
        'CatalogDeterminism', 'LayerOpeningReplay', 'LayerPath', 'LayerPriorRoot',
        'LayerRecoveryCorrect', 'LayerRecoveryHistory', 'LayerSignCorrect', 'LayerSignOpening',
        'LayerSignWitness', 'LayerWitness', 'LayerWotsSign', 'MerkleBuilderWots',
        'MerkleRootPersistence', 'MerkleRootWitness', 'MerkleWotsLeaves', 'RawMerkleRootWitness',
        'WotsCatalog', 'WotsCatalogOracle', 'WotsRootDeterminism', 'ActualSignerCorrect',
        'ForestOpening', 'SignerComponentHistory', 'SignerCoordinates', 'SignerFinishRecorded',
        'SignerFinishState', 'SignerFinishWitness', 'SignerForestStep', 'SignerGrindRoot',
        'SignerLayerStep', 'SignerLayerTrace', 'SignerRecoveryStep', 'SignerReturnedOpening',
        'SignerVerifierReplay', 'ActualByteSignerCorrect', 'EncodedLayer', 'EncodedSignature',
        'EncodedSignatureSlices', 'EncodedSlices', 'IndependentSignerWidth', 'IndependentWidths',
        'RawByteValues', 'RawCompositeBytes', 'RawSignerBytes', 'RawTreeBytes',
        'RawWotsBytes', 'SignerEncodingCorrect',
    )),
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'HonestByteContext', 'HonestByteCost', 'HonestBytePhysical', 'MemoNodeCollision',
        'NodeCollisionEvents', 'NodeDistribution', 'ProjectedBirthday', 'ProjectedMemoOracle',
        'PublicCollisionBound', 'PublicCollisionGame', 'BytePublicCollision', 'PublicCollisionState',
        'BytePublicNodeBad', 'PublicNodeZero', 'WotsZeroSentinel',
    )),
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'LayerBuildExtraction', 'LayerExtractionHistory', 'LayerWotsExtraction', 'LinearCollision',
        'RawRecoveryTrace', 'RawWotsExtraction', 'RecoveryCompression', 'RecoveryTraceOracle',
        'VerifierWotsOpening', 'VerifierWotsReplay', 'WotsKeyExtraction', 'WotsRecoveryHistory',
        'WotsRecoveryTrace',
    )),
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'ByteGameTopExtraction', 'ByteTopOpeningHop', 'RootCoverage', 'RootExtractionHistory',
        'RootLayerExtraction', 'RootSessionHistory', 'SessionTopExtraction', 'TopVerifierOpening',
        'VerifierTopExtraction',
    )),
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'ByteGameSubtreeExtraction', 'ByteSubtreeOpeningHop', 'HonestSubtreeMessages', 'LayerRecordExtraction',
        'LayerRecoveryRecord', 'LayerReturnedRoot', 'SessionSubtreeExtraction', 'SignerSubtreeReference',
        'SubtreeOpeningCases', 'VerifierLayerRecords',
    )),
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'ByteForestOpeningHop', 'ByteGameForestExtraction', 'ForestCoordinates', 'ForestOpeningCases',
        'ForestRecordExtraction', 'ForestRecoveryRecord', 'ForestReferenceHistory', 'ForestRootPrefix',
        'ForestRootRecording', 'ForestRootWitness', 'ForsRecordExtraction', 'ForsReturnedRoot',
        'ForsRootRecording', 'ForsRootWitness', 'HonestForestMessages', 'SessionForestExtraction',
        'SignerForestReference', 'VerifierForestRecords',
    )),
    *(PORT + 'tools/fullsign_model/' + f for f in (
        'Cargo.toml', 'Cargo.lock', 'check.py', 'src/main.rs')),

)


def check(root=ROOT):
    manifest = json.loads((root / PORT / 'cert-source-binding.json').read_text())
    if manifest.get('schema') != 1 or set(manifest['sources']) != set(SOURCES):
        raise ValueError('unexpected source-binding schema or source set')
    for name in SOURCES:
        got = hashlib.sha256((root / name).read_bytes()).hexdigest()
        if got != manifest['sources'][name]:
            raise ValueError(f'source binding changed: {name}')
    print(f'OK EasyCrypt manual source binding: {len(SOURCES)} inputs (not extraction)')


if __name__ == '__main__':
    try:
        check()
    except (OSError, ValueError, KeyError) as error:
        sys.exit(f'FAIL: {error}')
