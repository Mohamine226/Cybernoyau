"""Valide l'extracteur EMBER v2 (pefile) contre le code OFFICIEL (LIEF) sur de vrais executables.

    pip install "lief==0.14.1"          # version ancienne : necessite un Python <= 3.12
    python tools/validate_ember_features.py chemin\\vers\\programme.exe [autres.exe ...]

Telecharge a la volee le code officiel (elastic/ember, licence AGPL-3.0) dans un dossier TEMPORAIRE :
il n'est jamais copie dans ce depot. Applique 3 correctifs de compatibilite (numpy recent,
exceptions LIEF >= 0.14, hachage du nom de section sous scikit-learn recent), calcule les deux
vecteurs et compare bloc par bloc. Resultat attendu : tous les blocs identiques, sauf
`general[5]` (has_relocations) car LIEF >= 0.12 ne lit plus les relocations par defaut alors que le
jeu BODMAS (LIEF 0.9) les lisait : notre extracteur suit la definition d'origine.
"""
import importlib.util
import re
import sys
import tempfile
import urllib.request
from pathlib import Path

import numpy as np

import _common  # noqa: F401
from cubernoyau.features import ember_v2

URL = "https://raw.githubusercontent.com/elastic/ember/master/ember/features.py"
BLOCKS = [("histogramme", 0, 256), ("octets/entropie", 256, 512), ("chaines", 512, 616), ("general", 616, 626),
          ("en-tete", 626, 688), ("sections", 688, 943), ("imports", 943, 2223), ("exports", 2223, 2351),
          ("repertoires", 2351, 2381)]


def load_official():
    src = urllib.request.urlopen(URL, timeout=30).read().decode()      # noqa: S310
    src = re.sub(r"np\.int\b", "np.int64", src)
    src = src.replace("(lief.bad_format, lief.bad_file, lief.pe_error, lief.parser_error, lief.read_out_of_bound,\n"
                      "                       RuntimeError)", "(RuntimeError, ValueError)")
    src = src.replace("transform([raw_obj['entry']])", "transform([list(raw_obj['entry'])])")
    path = Path(tempfile.mkdtemp()) / "ember_official.py"
    path.write_text(src)
    spec = importlib.util.spec_from_file_location("ember_official", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.PEFeatureExtractor(feature_version=2, print_feature_warning=False)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    official = load_official()
    for name in sys.argv[1:]:
        data = Path(name).read_bytes()
        ours, ref = ember_v2.feature_vector(data), official.feature_vector(data)
        bad = [(label, [int(i) for i in np.where(~np.isclose(ours[a:b], ref[a:b], rtol=1e-4, atol=1e-4))[0]])
               for label, a, b in BLOCKS if not np.allclose(ours[a:b], ref[a:b], rtol=1e-4, atol=1e-4)]
        print(Path(name).name, "identique" if not bad else f"differences : {bad}")
