"""Local embeddings via Ollama's nomic-embed-text, cached on disk.

Everything stays on the machine: the CIS and ISO shards are copyrighted and a
hosted embedding API would be redistribution. nomic-embed-text is 137M
parameters and runs on CPU at ~12 texts/sec here, so the full 4-framework
catalogue embeds in minutes and then never again -- the cache is keyed by a
hash of the text, so re-running after a catalogue change only embeds the diff.
"""
from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path

import numpy as np

MODEL = "nomic-embed-text"
URL = "http://localhost:11434/api/embed"
DIM = 768


def _key(text: str) -> str:
    return hashlib.sha256(f"{MODEL}\x00{text}".encode()).hexdigest()[:32]


def _post(texts: list[str], timeout=600) -> list[list[float]]:
    req = urllib.request.Request(
        URL, data=json.dumps({"model": MODEL, "input": texts}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)["embeddings"]


class EmbeddingCache:
    def __init__(self, path="reference/.embed_cache.npz"):
        self.path = Path(path)
        self.vecs: dict[str, np.ndarray] = {}
        if self.path.exists():
            z = np.load(self.path, allow_pickle=False)
            self.vecs = {k: z[k] for k in z.files}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(self.path, **self.vecs)

    def encode(self, texts: list[str], *, batch=48, progress=None,
               truncate=2000) -> np.ndarray:
        """Embed, using the cache for anything already seen."""
        texts = [t[:truncate] for t in texts]
        todo = [t for t in dict.fromkeys(texts) if _key(t) not in self.vecs]
        for i in range(0, len(todo), batch):
            chunk = todo[i:i + batch]
            for vec, t in zip(_post(chunk), chunk):
                self.vecs[_key(t)] = np.asarray(vec, dtype=np.float32)
            if progress:
                progress(min(i + batch, len(todo)), len(todo))
        out = np.stack([self.vecs[_key(t)] for t in texts])
        # Normalise once so cosine is a dot product.
        return out / (np.linalg.norm(out, axis=1, keepdims=True) + 1e-9)
