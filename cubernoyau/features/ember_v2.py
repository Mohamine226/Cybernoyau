"""Caracteristiques EMBER v2 (2381 valeurs) calculees avec pefile, sans LIEF.

Reproduit le FORMAT de caracteristiques publie avec les jeux EMBER / BODMAS
(Anderson & Roth, 2018, arXiv:1804.04637) afin d'appliquer a vos propres
fichiers un modele entraine sur ces jeux de donnees.

LICENCE - a lire : le code de reference (github.com/elastic/ember) est sous
AGPL-3.0 (donnees sous MIT). Ce fichier est une reecriture independante a base
de pefile, VALIDEE en comparant ses sorties au code officiel sur de vrais
executables (voir tools/validate_ember_features.py, qui telecharge le code
officiel a la volee sans l'inclure dans ce depot). Comme le format et la logique
sont identiques par construction, si vous DISTRIBUEZ ce logiciel, faites
verifier la question de la licence (publier sous AGPL-3.0 ou remplacer ce
module) avant diffusion.

Differences volontaires avec le code de reference :
 - pefile (Python pur, disponible partout) remplace LIEF (dont la version 0.9
   d'origine n'existe plus pour les Python recents) ;
 - le calcul de l'histogramme octets/entropie est vectorise (meme resultat) ;
 - le nom de la section d'entree est decoupe en caracteres, comme le faisait
   la version de scikit-learn utilisee pour fabriquer les vecteurs d'origine.
Ordre du vecteur : histogramme (256), octets/entropie (256), chaines (104),
general (10), en-tete (62), sections (255), imports (1280), exports (128),
repertoires de donnees (30).
"""

import re
from pathlib import Path

import numpy as np
from sklearn.feature_extraction import FeatureHasher

DIM = 2381
MAX_BYTES = 100 * 1024 * 1024        # au-dela, le modele n'est pas applique

_MACHINE = {0x0: "UNKNOWN", 0x1d3: "AM33", 0x8664: "AMD64", 0x1c0: "ARM", 0x1c4: "ARMNT",
            0xaa64: "ARM64", 0xebc: "EBC", 0x14c: "I386", 0x200: "IA64", 0x9041: "M32R",
            0x266: "MIPS16", 0x366: "MIPSFPU", 0x466: "MIPSFPU16", 0x1f0: "POWERPC",
            0x1f1: "POWERPCFP", 0x166: "R4000", 0x5032: "RISCV32", 0x5064: "RISCV64",
            0x5128: "RISCV128", 0x1a2: "SH3", 0x1a3: "SH3DSP", 0x1a6: "SH4", 0x1a8: "SH5",
            0x1c2: "THUMB", 0x169: "WCEMIPSV2"}
_CHARS = [(0x1, "RELOCS_STRIPPED"), (0x2, "EXECUTABLE_IMAGE"), (0x4, "LINE_NUMS_STRIPPED"),
          (0x8, "LOCAL_SYMS_STRIPPED"), (0x10, "AGGRESSIVE_WS_TRIM"), (0x20, "LARGE_ADDRESS_AWARE"),
          (0x80, "BYTES_REVERSED_LO"), (0x100, "NEED_32BIT_MACHINE"), (0x200, "DEBUG_STRIPPED"),
          (0x400, "REMOVABLE_RUN_FROM_SWAP"), (0x800, "NET_RUN_FROM_SWAP"), (0x1000, "SYSTEM"),
          (0x2000, "DLL"), (0x4000, "UP_SYSTEM_ONLY"), (0x8000, "BYTES_REVERSED_HI")]
_DLLCHARS = [(0x20, "HIGH_ENTROPY_VA"), (0x40, "DYNAMIC_BASE"), (0x80, "FORCE_INTEGRITY"),
             (0x100, "NX_COMPAT"), (0x200, "NO_ISOLATION"), (0x400, "NO_SEH"), (0x800, "NO_BIND"),
             (0x1000, "APPCONTAINER"), (0x2000, "WDM_DRIVER"), (0x4000, "GUARD_CF"),
             (0x8000, "TERMINAL_SERVER_AWARE")]
_SUBSYSTEM = {0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS2_CUI",
              7: "POSIX_CUI", 9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION",
              11: "EFI_BOOT_SERVICE_DRIVER", 12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM",
              14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION"}
_SECCHARS = [(0x8, "TYPE_NO_PAD"), (0x20, "CNT_CODE"), (0x40, "CNT_INITIALIZED_DATA"),
             (0x80, "CNT_UNINITIALIZED_DATA"), (0x100, "LNK_OTHER"), (0x200, "LNK_INFO"),
             (0x800, "LNK_REMOVE"), (0x1000, "LNK_COMDAT"), (0x8000, "GPREL"),
             (0x20000, "MEM_PURGEABLE"), (0x40000, "MEM_LOCKED"), (0x80000, "MEM_PRELOAD"),
             (0x1000000, "LNK_NRELOC_OVFL"), (0x2000000, "MEM_DISCARDABLE"),
             (0x4000000, "MEM_NOT_CACHED"), (0x8000000, "MEM_NOT_PAGED"),
             (0x10000000, "MEM_SHARED"), (0x20000000, "MEM_EXECUTE"), (0x40000000, "MEM_READ"),
             (0x80000000, "MEM_WRITE")]

_H = {n: FeatureHasher(n, input_type="string") for n in (10, 50, 128, 256, 1024)}
_HP = FeatureHasher(50, input_type="pair")
_STR = re.compile(rb"[\x20-\x7f]{5,}")
_PATHS = re.compile(rb"c:\\\\", re.IGNORECASE)
_URLS = re.compile(rb"https?://", re.IGNORECASE)
_REG = re.compile(rb"HKEY_")
_MZ = re.compile(rb"MZ")


def _hash(n, tokens):
    """Projette une liste de mots dans un vecteur de `n` cases par hachage (FeatureHasher)."""
    return _H[n].transform([tokens]).toarray()[0]


def byte_histogram(a):
    """Part de chaque valeur d'octet (0..255) dans le fichier."""
    c = np.bincount(a, minlength=256).astype(np.float32)
    return c / c.sum() if c.sum() else c


def byte_entropy_histogram(a, window=2048, step=1024):
    """Histogramme 2D (entropie locale x valeur d'octet), fenetre de 2048 octets, pas de 1024."""
    out = np.zeros((16, 16), dtype=np.int64)

    def one(block_counts):
        p = block_counts.astype(np.float32) / window
        wh = np.where(block_counts)[0]
        h = np.sum(-p[wh] * np.log2(p[wh])) * 2
        return min(int(h * 2), 15)

    if a.shape[0] < window:
        out[one(np.bincount(a >> 4, minlength=16)), :] += np.bincount(a >> 4, minlength=16)
    else:
        m = a.shape[0] // step
        chunks = np.zeros((m, 16), dtype=np.int64)
        nib = (a[: m * step] >> 4).reshape(m, step)
        for v in range(16):
            chunks[:, v] = (nib == v).sum(axis=1)
        blocks = chunks[:-1] + chunks[1:]                       # fenetres de 2048 octets
        p = blocks.astype(np.float32) / window
        with np.errstate(divide="ignore", invalid="ignore"):
            terms = np.where(blocks > 0, -p * np.log2(np.where(p > 0, p, 1)), 0.0)
        hbin = np.minimum((terms.sum(axis=1) * 2 * 2).astype(np.int64), 15)
        np.add.at(out, hbin, blocks)
    flat = out.flatten().astype(np.float32)
    return flat / flat.sum() if flat.sum() else flat


def strings_features(b):
    """Statistiques des chaines imprimables : nombre, longueur, repartition, chemins, liens, cles de registre."""
    strs = _STR.findall(b)
    if strs:
        lengths = [len(s) for s in strs]
        avlen = sum(lengths) / len(lengths)
        joined = np.frombuffer(b"".join(strs), dtype=np.uint8) - 0x20
        c = np.bincount(joined, minlength=96)
        csum = int(c.sum())
        p = c.astype(np.float32) / csum
        wh = np.where(c)[0]
        ent = float(np.sum(-p[wh] * np.log2(p[wh])))
    else:
        avlen, c, csum, ent = 0, np.zeros(96, dtype=np.float32), 0, 0.0
    div = float(csum) if csum > 0 else 1.0
    return np.hstack([len(strs), avlen, csum, np.asarray(c) / div, ent, len(_PATHS.findall(b)),
                      len(_URLS.findall(b)), len(_REG.findall(b)), len(_MZ.findall(b))]).astype(np.float32)


def _names(value, table):
    """Noms des drapeaux actifs d'un champ de bits (ex. caracteristiques de l'en-tete PE)."""
    return [name for bit, name in table if value & bit]


def _entropy(data):
    """Entropie de Shannon d'une suite d'octets."""
    if not len(data):
        return 0.0
    c = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = c[c > 0] / c.sum()
    return float(-(p * np.log2(p)).sum())


def parse_pe(b):
    """Retourne l'objet pefile ou None si ce n'est pas un PE exploitable."""
    import pefile
    try:
        pe = pefile.PE(data=b, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        return pe
    except Exception:
        return None


def pe_features(b, pe):
    """general (10) + en-tete (62) + sections (255) + imports (1280) + exports (128) + dirs (30)."""
    n = len(b)
    if pe is None:
        general = [n, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        header = np.hstack([0, _hash(10, [""]), _hash(10, []), _hash(10, [""]), _hash(10, []),
                            _hash(10, [""]), [0] * 11])
        sections = np.hstack([[0] * 5, _HP.transform([[]]).toarray()[0], _HP.transform([[]]).toarray()[0],
                              _HP.transform([[]]).toarray()[0], _hash(50, []), _hash(50, [])])
        return (np.asarray(general, dtype=np.float32), header.astype(np.float32),
                sections.astype(np.float32), np.zeros(1280, np.float32),
                np.zeros(128, np.float32), np.zeros(30, np.float32))
    oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER
    dd = oh.DATA_DIRECTORY
    d = lambda i: (dd[i].Size if i < len(dd) else 0, dd[i].VirtualAddress if i < len(dd) else 0)  # noqa: E731
    imports = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        lib = entry.dll.decode("latin-1")
        lst = imports.setdefault(lib, [])
        for imp in entry.imports:
            lst.append(imp.name.decode("latin-1")[:10000] if imp.name else f"ordinal{imp.ordinal}")
    exports = [e.name.decode("latin-1")[:10000] if e.name else ""
               for e in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])]
    sym_ok = fh.PointerToSymbolTable and fh.PointerToSymbolTable < n
    general = [n, oh.SizeOfImage, int(d(6)[0] > 0), len(exports), sum(len(v) for v in imports.values()),
               int(d(5)[0] > 0), int(d(2)[0] > 0), int(d(4)[0] > 0), int(d(9)[0] > 0),
               fh.NumberOfSymbols if sym_ok else 0]
    magic = "PE32_PLUS" if oh.Magic == 0x20b else "PE32"
    header = np.hstack([
        fh.TimeDateStamp, _hash(10, [_MACHINE.get(fh.Machine, "UNKNOWN")]),
        _hash(10, _names(fh.Characteristics, _CHARS)),
        _hash(10, [_SUBSYSTEM.get(oh.Subsystem, "UNKNOWN")]),
        _hash(10, _names(oh.DllCharacteristics, _DLLCHARS)), _hash(10, [magic]),
        oh.MajorImageVersion, oh.MinorImageVersion, oh.MajorLinkerVersion, oh.MinorLinkerVersion,
        oh.MajorOperatingSystemVersion, oh.MinorOperatingSystemVersion, oh.MajorSubsystemVersion,
        oh.MinorSubsystemVersion, oh.SizeOfCode, oh.SizeOfHeaders, getattr(oh, "SizeOfHeapCommit", 0)])
    secs = []
    for s in pe.sections:
        # LIEF ne charge que min(taille virtuelle, taille brute) octets par section :
        # le remplissage (zeros) en fin de section est donc exclu du calcul d'entropie.
        length = min(s.SizeOfRawData, s.Misc_VirtualSize) if s.Misc_VirtualSize else s.SizeOfRawData
        raw = b[s.PointerToRawData: s.PointerToRawData + length] if s.PointerToRawData < n else b""
        secs.append({"name": s.Name.rstrip(b"\x00").decode("latin-1"), "size": s.SizeOfRawData,
                     "entropy": _entropy(raw), "vsize": s.Misc_VirtualSize,
                     "props": _names(s.Characteristics, _SECCHARS), "va": s.VirtualAddress})
    ep = oh.AddressOfEntryPoint
    entry = ""
    for s in secs:
        if s["va"] <= ep < s["va"] + max(s["vsize"], 1):
            entry = s["name"]
            break
    else:
        for s in secs:
            if "MEM_EXECUTE" in s["props"]:
                entry = s["name"]
                break
    general_s = [len(secs), sum(1 for s in secs if s["size"] == 0), sum(1 for s in secs if s["name"] == ""),
                 sum(1 for s in secs if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"]),
                 sum(1 for s in secs if "MEM_WRITE" in s["props"])]
    sections = np.hstack([
        general_s,
        _HP.transform([[(s["name"], s["size"]) for s in secs]]).toarray()[0],
        _HP.transform([[(s["name"], s["entropy"]) for s in secs]]).toarray()[0],
        _HP.transform([[(s["name"], s["vsize"]) for s in secs]]).toarray()[0],
        _hash(50, list(entry)),
        _hash(50, [p for s in secs if s["name"] == entry for p in s["props"]])])
    imp = np.hstack([_hash(256, list({k.lower() for k in imports})),
                     _hash(1024, [k.lower() + ":" + e for k, v in imports.items() for e in v])])
    dirs = np.zeros(30, np.float32)
    for i in range(15):
        dirs[2 * i], dirs[2 * i + 1] = d(i)
    return (np.asarray(general, dtype=np.float32), header.astype(np.float32), sections.astype(np.float32),
            imp.astype(np.float32), _hash(128, exports).astype(np.float32), dirs)


def feature_vector(data):
    """Vecteur EMBER v2 (2381 float32) a partir du contenu d'un fichier PE (bytes)."""
    a = np.frombuffer(data, dtype=np.uint8)
    pe = parse_pe(data)
    try:
        general, header, sections, imp, exp, dirs = pe_features(data, pe)
    finally:
        if pe is not None:
            pe.close()
    vec = np.hstack([byte_histogram(a), byte_entropy_histogram(a), strings_features(data),
                     general, header, sections, imp, exp, dirs]).astype(np.float32)
    assert vec.shape[0] == DIM, vec.shape
    return vec


def is_pe_bytes(head):
    return head[:2] == b"MZ"


def file_vector(path, max_bytes=MAX_BYTES):
    """Vecteur d'un fichier sur disque, ou None si ce n'est pas un PE ou s'il est trop gros."""
    p = Path(path)
    if p.stat().st_size > max_bytes:
        return None
    data = p.read_bytes()
    return feature_vector(data) if is_pe_bytes(data[:2]) else None
