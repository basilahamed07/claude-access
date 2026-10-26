export const MAX_CHUNK_LINES = 5_000;
export const MAX_CHUNK_BYTES = 1_000_000;

/** Split a log file into batches the API accepts. CSV batches each repeat the header row. */
export function chunkLog(text: string, format: string): string[][] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() !== "");
  const header = format === "csv" ? lines.shift() : undefined;
  const chunks: string[][] = [];
  let cur: string[] = [];
  let bytes = 0;
  for (const line of lines) {
    const size = line.length + 1;
    if (cur.length > 0 && (cur.length >= MAX_CHUNK_LINES || bytes + size > MAX_CHUNK_BYTES)) { chunks.push(cur); cur = []; bytes = 0; }
    cur.push(line.slice(0, 4000));
    bytes += Math.min(size, 4001);
  }
  if (cur.length > 0) chunks.push(cur);
  return header ? chunks.map((c) => [header, ...c]) : chunks;
}

/** A stable id for a file's content, so uploading the same file twice is counted once. */
export async function fileBatchPrefix(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].slice(0, 8).map((b) => b.toString(16).padStart(2, "0")).join("");
}
