import fs from 'node:fs';
import path from 'node:path';

/**
 * The root of the repository a script lives in: the nearest folder at or above `startDir` that has a `.git` entry. Where there is none
 * (a copy without its history, such as a container image) `fallback` is used, so the answer does not depend on how deep the checkout
 * is nested inside some other folder.
 */
export function repoRootFrom(startDir: string, fallback: string): string {
  let dir = path.resolve(startDir);
  for (;;) {
    if (fs.existsSync(path.join(dir, '.git'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return path.resolve(fallback);
    dir = parent;
  }
}
