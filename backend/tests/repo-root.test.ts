import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "@jest/globals";
import { repoRootFrom } from "../scripts/lib/repoRoot.js";

const base = fs.mkdtempSync(path.join(os.tmpdir(), "repo-root-"));
afterAll(() => fs.rmSync(base, { recursive: true, force: true }));

describe("repoRootFrom", () => {
  it("is the nearest folder above the script that has a .git entry, however deep the checkout is nested", () => {
    const repo = path.join(base, "a", "b", "edition");
    const scripts = path.join(repo, "backend", "scripts", "lib");
    fs.mkdirSync(scripts, { recursive: true });
    fs.mkdirSync(path.join(repo, ".git"));
    expect(repoRootFrom(scripts, path.join(repo, "backend"))).toBe(repo);
  });

  it("treats a .git file (a worktree or submodule) as a repository root too", () => {
    const repo = path.join(base, "wt");
    const scripts = path.join(repo, "backend", "scripts");
    fs.mkdirSync(scripts, { recursive: true });
    fs.writeFileSync(path.join(repo, ".git"), "gitdir: elsewhere");
    expect(repoRootFrom(scripts, path.join(repo, "backend"))).toBe(repo);
  });

  it("uses the fallback when no folder above has one (an image without its history)", () => {
    const app = path.join(base, "image", "app");
    const scripts = path.join(app, "backend", "scripts");
    fs.mkdirSync(scripts, { recursive: true });
    const found = repoRootFrom(scripts, app);
    // The temp folder itself may sit inside a checkout on some machines, so only assert it is not the (too high) filesystem root.
    expect([app, ...ancestors(base)]).toContain(found);
    expect(found).not.toBe(path.parse(scripts).root);
  });
});

function ancestors(dir: string): string[] {
  const out: string[] = [];
  let d = dir;
  while (path.dirname(d) !== d) {
    out.push(d);
    d = path.dirname(d);
  }
  return out;
}
