// Config path diff helper used by gateway mutation diagnostics.
import { isDeepStrictEqual } from "node:util";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { isPlainObject } from "../utils.js";

/** Return dotted config paths whose values differ between two config snapshots. */
export function diffConfigPaths(prev: unknown, next: unknown, prefix = ""): string[] {
  if (prev === next) {
    return [];
  }
  if (isPlainObject(prev) && isPlainObject(next)) {
    const keys = new Set([...Object.keys(prev), ...Object.keys(next)]);
    const paths: string[] = [];
    for (const key of keys) {
      const prevValue = prev[key];
      const nextValue = next[key];
      if (prevValue === undefined && nextValue === undefined) {
        continue;
      }
      const childPrefix = prefix ? `${prefix}.${key}` : key;
      const childPaths = diffConfigPaths(prevValue, nextValue, childPrefix);
      if (childPaths.length > 0) {
        paths.push(...childPaths);
      }
    }
    return paths;
  }
  if (Array.isArray(prev) && Array.isArray(next)) {
    // Arrays can contain object entries (for example memory.qmd.paths/scope.rules);
    // compare structurally so identical values are not reported as changed.
    if (isDeepStrictEqual(prev, next)) {
      return [];
    }
  }
  return [prefix || "<root>"];
}

/** Preserve startup-only restart boundaries hidden by whole-object config changes. */
export function diffGatewayReloadPaths(
  prevConfig: OpenClawConfig,
  nextConfig: OpenClawConfig,
): string[] {
  const changedPaths = diffConfigPaths(prevConfig, nextConfig);
  if (!changedPaths.includes("mcp")) {
    return changedPaths;
  }
  // Adding or removing the whole `mcp` object collapses to the broad `mcp`
  // path. Preserve the Apps boundary so the listener still restarts.
  return [
    ...changedPaths,
    ...diffConfigPaths(
      { mcp: { apps: prevConfig.mcp?.apps } },
      { mcp: { apps: nextConfig.mcp?.apps } },
    ),
  ];
}

/** Expand an added object only as far as needed to distinguish writer-applied leaves. */
export function expandChangedPathsForAppliedLeaves(
  previous: OpenClawConfig,
  next: OpenClawConfig,
  changedPaths: string[],
  appliedPaths: readonly string[],
): string[] {
  if (appliedPaths.length === 0) {
    return changedPaths;
  }
  const valueAt = (config: unknown, path: string): unknown =>
    path
      .split(".")
      .reduce<unknown>((value, key) => (isPlainObject(value) ? value[key] : undefined), config);
  const expand = (path: string, before: unknown, after: unknown): string[] => {
    if (!appliedPaths.some((applied) => applied.startsWith(`${path}.`))) {
      return [path];
    }
    if (!isPlainObject(before) && !isPlainObject(after)) {
      return [path];
    }
    const beforeRecord = isPlainObject(before) ? before : {};
    const afterRecord = isPlainObject(after) ? after : {};
    return [...new Set([...Object.keys(beforeRecord), ...Object.keys(afterRecord)])].flatMap(
      (key) => {
        const childPath = `${path}.${key}`;
        const beforeValue = beforeRecord[key];
        const afterValue = afterRecord[key];
        return diffConfigPaths(beforeValue, afterValue, childPath).length > 0
          ? expand(childPath, beforeValue, afterValue)
          : [];
      },
    );
  };
  return changedPaths.flatMap((path) => expand(path, valueAt(previous, path), valueAt(next, path)));
}
