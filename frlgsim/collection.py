"""Offline collection audit and resumable, one-at-a-time trade ledger."""

from collections import Counter
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid

from .mon import Mon, to_decrypted
from .species import SPECIES


# Internal Gen-3 species and item IDs, from pret/pokefirered's evolution table.
TRADE_EVOLUTIONS = {64: "Alakazam", 67: "Machamp", 75: "Golem", 93: "Gengar"}
ITEM_EVOLUTIONS = {(61, 187): "Politoed", (79, 187): "Slowking", (95, 199): "Steelix",
                   (123, 199): "Scizor", (117, 201): "Kingdra", (137, 218): "Porygon2",
                   (373, 192): "Huntail", (373, 193): "Gorebyss"}


def inspect_file(path):
    path = Path(path).expanduser().resolve()
    data = path.read_bytes()
    if path.suffix.lower() not in (".pk3", ".ek3"):
        raise ValueError("expected a .pk3 or .ek3 file")
    pokemon = Mon.from_pk3(data, encrypted=path.suffix.lower() == ".ek3")
    canonical = to_decrypted(pokemon.raw)
    decoded = pokemon.decode()
    species = decoded["species"]
    if species not in SPECIES:
        raise ValueError(f"empty or unsupported Gen-3 species ID {species}")
    if canonical[19] & 1:
        raise ValueError("Bad Egg flag is set")
    ivs = int.from_bytes(canonical[72:76], "little")
    if ivs & (1 << 30) or canonical[19] & 4:
        raise ValueError("egg; a living-dex entry must be hatched")
    pid, otid = decoded["pid"], decoded["otid"]
    shiny = ((pid & 65535) ^ (pid >> 16) ^ (otid & 65535) ^ (otid >> 16)) < 8
    item = decoded["heldItem"]
    evolves_to = None
    if item != 195:  # Gen 3 Everstone prevents trade evolution.
        evolves_to = TRADE_EVOLUTIONS.get(species) or ITEM_EVOLUTIONS.get((species, item))
    warnings = []
    if evolves_to:
        warnings.append(f"Will evolve into {evolves_to} when traded. Preserve the species with "
                        "an Everstone in a separate prepared copy before importing.")
    if species in (151, 410) and not canonical[79] & 128:
        warnings.append("Mew/Deoxys has no fateful-encounter flag; the game may reject this trade.")
    if decoded["level"] is None or not 1 <= decoded["level"] <= 100:
        raise ValueError("level is outside 1..100")
    dex, name = SPECIES[species]
    return {"sha256": hashlib.sha256(data).hexdigest(), "path": str(path),
            "dex": dex, "species": species, "name": name, "nickname": decoded["nickname"],
            "shiny": shiny, "level": decoded["level"], "held_item": item,
            "evolves_to": evolves_to, "warnings": warnings}


def audit(directory):
    root = Path(directory).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("collection must be an existing directory")
    entries, errors = [], []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in (".pk3", ".ek3"):
            try:
                entries.append(inspect_file(path))
            except (OSError, ValueError) as exc:
                errors.append({"path": str(path), "error": str(exc)})
    counts = Counter(entry["dex"] for entry in entries)
    shiny_dex = {entry["dex"] for entry in entries if entry["shiny"]}
    return {"root": str(root), "entries": entries, "errors": errors, "valid_files": len(entries),
            "unique_species": len(counts), "shiny_species": len(shiny_dex),
            "missing_dex": sorted(set(range(1, 387)) - counts.keys()),
            "missing_shiny_dex": sorted(set(range(1, 387)) - shiny_dex),
            "duplicate_species": sorted(dex for dex, count in counts.items() if count > 1)}


class Workspace:
    """A transaction is recorded before launching the radio; uncertain trades need review.

    No process exit code or received file is proof that the Switch saved a trade.
    Completion always comes from explicit on-console verification by the operator.
    """

    def __init__(self, path):
        self.root = Path(path).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.root / "collection.sqlite3", timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS pokemon (
                sha256 TEXT PRIMARY KEY, path TEXT NOT NULL, dex INTEGER NOT NULL,
                name TEXT NOT NULL, shiny INTEGER NOT NULL, metadata TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'review', 'confirmed'))
            );
            CREATE TABLE IF NOT EXISTS attempts (
                id TEXT PRIMARY KEY, sha256 TEXT NOT NULL REFERENCES pokemon(sha256),
                status TEXT NOT NULL CHECK(status IN ('review', 'confirmed', 'not_traded')),
                returncode INTEGER, created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_unresolved_attempt
                ON attempts(status) WHERE status = 'review';
        """)

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def import_report(self, report):
        if report["errors"] or not report["entries"]:
            raise ValueError("import requires at least one valid file and no invalid files; run audit first")
        if self.root.is_relative_to(Path(report["root"])):
            raise ValueError("the transfer workspace must be outside the source collection")
        # Keep outputs out of the input tree, so received trade fodder cannot be re-imported.
        for entry in report["entries"]:
            if Path(entry["path"]).is_relative_to(self.root):
                raise ValueError("the transfer workspace must be outside the source collection")
        before = self.db.total_changes
        with self.transaction():
            for entry in report["entries"]:
                self.db.execute("""INSERT INTO pokemon(sha256,path,dex,name,shiny,metadata)
                    VALUES(?,?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET
                    path=excluded.path, metadata=excluded.metadata""",
                    (entry["sha256"], entry["path"], entry["dex"], entry["name"],
                     entry["shiny"], json.dumps(entry)))
        return self.db.total_changes - before

    def rows(self):
        return [dict(row) for row in self.db.execute(
            "SELECT sha256,path,dex,name,shiny,status,metadata FROM pokemon ORDER BY dex,sha256")]

    def unresolved(self):
        return self.db.execute("SELECT * FROM attempts WHERE status='review'").fetchone()

    def next_entry(self):
        if self.unresolved():
            raise ValueError("an earlier attempt needs review; run status, then resolve it before trading")
        row = self.db.execute("SELECT metadata FROM pokemon WHERE status='pending' "
                              "ORDER BY dex,sha256 LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None

    def prepare(self, *, allow_evolution=False):
        # Exclusive claim is made BEFORE any network activity, including across processes.
        with self.transaction():
            entry = self.next_entry()
            if entry is None:
                raise ValueError("no pending Pokemon")
            source = Path(entry["path"])
            data = source.read_bytes()
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError("source file changed since import; restore the imported original before trading")
            if entry["evolves_to"] and not allow_evolution:
                raise ValueError(entry["warnings"][0] + " Use --allow-evolution only if intentional.")
            attempt = uuid.uuid4().hex
            folder = self.root / "attempts" / attempt
            folder.mkdir(parents=True)
            # Two party slots follow upstream's documented, tested single-trade setup.
            # Slot 0 is retained; slot 1 is offered. They may contain the same file bytes.
            offer = folder / ("offer" + source.suffix.lower())
            with offer.open("xb") as stream:
                stream.write(data)
            self.db.execute("INSERT INTO attempts(id,sha256,status) VALUES(?,?,'review')",
                            (attempt, entry["sha256"]))
            self.db.execute("UPDATE pokemon SET status='review' WHERE sha256=?", (entry["sha256"],))
        return attempt, offer, folder / "received.pk3", entry

    def record_exit(self, attempt, code):
        with self.db:
            self.db.execute("UPDATE attempts SET returncode=? WHERE id=?", (code, attempt))

    def resolve(self, attempt, outcome):
        if outcome not in ("confirmed", "not_traded"):
            raise ValueError("outcome must be confirmed or not_traded")
        with self.transaction():
            row = self.db.execute("SELECT * FROM attempts WHERE id=?", (attempt,)).fetchone()
            if not row or row["status"] != "review":
                raise ValueError("attempt does not exist or has already been resolved")
            self.db.execute("UPDATE attempts SET status=? WHERE id=?", (outcome, attempt))
            self.db.execute("UPDATE pokemon SET status=? WHERE sha256=?",
                            ("confirmed" if outcome == "confirmed" else "pending", row["sha256"]))
