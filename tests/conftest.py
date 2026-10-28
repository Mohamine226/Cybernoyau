import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Isole la base et les donnees avant tout import de l'application.
_TMP = tempfile.mkdtemp(prefix="cubernoyau_tests_")
os.environ["CUBERNOYAU_DATA"] = _TMP
os.environ["CUBERNOYAU_DB"] = os.path.join(_TMP, "test.db")
os.environ["CUBERNOYAU_AUTOSTART"] = "0"
os.environ["CUBERNOYAU_WATCH"] = os.path.join(_TMP, "nonexistent")
