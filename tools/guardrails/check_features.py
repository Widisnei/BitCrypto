#!/usr/bin/env python3
import pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

anchors = {
    "miniscript.h": "BitCrypto.Tx/include/bitcrypto/tx/miniscript.h",
    "tapscript.h":  "BitCrypto.Tx/include/bitcrypto/tx/tapscript.h",
    "psbt_v2_sign.h": "BitCrypto.PSBTv2/include/bitcrypto/psbt2/psbt_v2_sign.h",
    "psbt_v2_verify.h": "BitCrypto.PSBTv2/include/bitcrypto/psbt2/psbt_v2_verify.h",
    "MSCLI": "BitCrypto.MSCLI/src/main.cpp",
    "PSBTCLI": "BitCrypto.PSBTCLI/src/main.cpp",
    "BenchCLI": "BitCrypto.BenchCLI/src/main.cpp",
    "SchnorrCLI": "BitCrypto.SchnorrCLI/src/main.cpp",
    "PuzzleCLI": "BitCrypto.PuzzleCLI/src/main.cpp",
    "WSCLI": "BitCrypto.WSCLI/src/main.cpp",
    "PSBTv2": "BitCrypto.PSBTv2/include/bitcrypto/psbt2/psbt_v2.h",
    "msm_pippenger.h": "BitCrypto.Core/include/bitcrypto/msm_pippenger.h",
    "endo_shamir.h": "BitCrypto.Core/include/bitcrypto/endo_shamir.h",
    "musig2.h": "BitCrypto.Schnorr/include/bitcrypto/schnorr/musig2.h",
}

tokens = {
    "miniscript.h": ["sortedmulti(", "wsh(", "sh(", "after(", "older(", "and(", "or_i(", "or_c(", "thresh("],
    "tapscript.h":  ["tapleaf_hash", "ser_compact_size"],
    "psbt_v2_sign.h": ["P2SH-P2WPKH", "P2SH-P2WSH", "is_p2tr", "parse_wscript_multisig"],
    "psbt_v2_verify.h": ["verify_psbt2"],
    "MSCLI": ["--tapscript-from-ms", "--wpkh-from-ms", "--p2shwpkh-from-ms", "--suggest-lock", "--taptree-pair-by-hash"],
    "PSBTCLI": ["--psbt2-pretty", "--psbt2-decode", "--psbt2-verify"],
    "BenchCLI": ["--cpu-sha256-bytes", "--gpu-sha256-bytes", "--iters"],
    "SchnorrCLI": ["--bip340-verify"],
    "PuzzleCLI": ["--kangaroo"],
    "WSCLI": ["witness_items=", "witness_sizes=", "witness_preview=", "tap_control_block_depth="],
    "PSBTv2": ["unknown_in_kv"],
    "msm_pippenger.h": ["wNAF", "precompute"],
    "endo_shamir.h": ["endomorphism", "Shamir"],
    "musig2.h": ["MuSig2"],
}

ok = True
for key, rel in anchors.items():
    p = ROOT / rel
    if not p.exists():
        print("[FALTA]", rel)
        ok = False
        continue
    txt = p.read_text(encoding="utf-8", errors="ignore")
    for tok in tokens.get(key, []):
        if tok not in txt:
            print("[FALTA TOKEN]", rel, "=>", tok)
            ok = False

print("Features OK" if ok else "Features INCOMPLETO")
sys.exit(0 if ok else 1)

