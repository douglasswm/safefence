import fs from "node:fs";
import path from "node:path";

export class JsonlWriter {
  private readonly fd: number;

  constructor(filePath: string) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    this.fd = fs.openSync(filePath, "a");
  }

  append(record: unknown): void {
    fs.writeSync(this.fd, JSON.stringify(record) + "\n");
  }

  close(): void {
    fs.fsyncSync(this.fd);
    fs.closeSync(this.fd);
  }
}

export function readJsonlFile<T>(filePath: string): T[] {
  if (!fs.existsSync(filePath)) return [];
  const records: T[] = [];
  for (const line of fs.readFileSync(filePath, "utf-8").split("\n")) {
    if (!line) continue;
    try {
      records.push(JSON.parse(line) as T);
    } catch {
      // skip malformed lines
    }
  }
  return records;
}
