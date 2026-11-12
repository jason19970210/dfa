import { homedir } from "node:os";
import { delimiter, join } from "node:path";

/** dfa's own writable home. Everything dfa writes lives under it. */
export function dfaHome(): string {
  return process.env.DFA_HOME ?? join(homedir(), ".dfa");
}

/**
 * XDG cache root handed to vol: Volatility creates $XDG_CACHE_HOME/volatility3
 * at import time, before --cache-path is parsed, so the env var is what keeps
 * that write inside dfa's home.
 */
export function xdgCacheHome(): string {
  return join(dfaHome(), "cache");
}

/** Volatility cache, pinned under dfa's home instead of the user cache. */
export function volCacheDir(): string {
  return join(xdgCacheHome(), "volatility3");
}

/** Environment for every vol child process. */
export function volEnv(): NodeJS.ProcessEnv {
  return { ...process.env, XDG_CACHE_HOME: xdgCacheHome() };
}

/** Extra Volatility symbol directories (ISF), from DFA_SYMBOL_DIRS. */
export function symbolDirs(): string[] {
  return (process.env.DFA_SYMBOL_DIRS ?? "").split(delimiter).filter(Boolean);
}

export function custodyPath(): string {
  return process.env.DFA_CUSTODY_LOG ?? join(dfaHome(), "custody.jsonl");
}

export function reportDir(): string {
  return process.env.DFA_REPORT_DIR ?? join(dfaHome(), "reports");
}
