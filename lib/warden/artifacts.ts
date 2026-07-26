export type StoredArtifact = {
  id: string;
  createdAt: number;
  expiresAt: number;
  data: unknown;
};

const artifactCache = new Map<string, StoredArtifact>();

export function storeArtifact(id: string, data: unknown, ttlMs: number = 600_000): string {
  const now = Date.now();
  // Bound LRU to maximum 500 artifacts
  if (artifactCache.size >= 500) {
    const oldestKey = artifactCache.keys().next().value;
    if (oldestKey) artifactCache.delete(oldestKey);
  }

  artifactCache.set(id, {
    id,
    createdAt: now,
    expiresAt: now + ttlMs,
    data,
  });

  return id;
}

export function getArtifact(id: string): unknown | null {
  const artifact = artifactCache.get(id);
  if (!artifact) return null;

  if (Date.now() > artifact.expiresAt) {
    artifactCache.delete(id);
    return null;
  }

  return artifact.data;
}
