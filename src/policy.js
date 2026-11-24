/* policy.js: counterfactual blast-radius simulation and the deterministic
   CI/CD policy gate. Everything derives from the local analysis only; no
   registry, advisory feed, or network is ever consulted. */

import { analyze, simulate } from './detectors.js';
import { breadthFirst, compare, indexGraph } from './graph.js';

const SEV_RANK = { high: 0, medium: 1, low: 2 };
const SEV_NAME = ['high', 'medium', 'low'];
const HOOK_RULES = new Set(['SG003', 'SG004', 'SG005', 'SG006']);
const TYPO_RULES = new Set(['SG001', 'SG002']);
const UNPINNED_RULES = new Set(['SG009']);
export const GATE_LEVELS = Object.freeze(['off', 'warn', 'block']);
export const CEILINGS = Object.freeze(['off', 'high', 'medium', 'low']);

export const DEFAULT_POLICY = Object.freeze({
  installScripts: 'block',
  typosquat: 'warn',
  typosquatMax: 0,
  unpinned: 'warn',
  unpinnedMax: 0,
  severityCeiling: 'high',
  licenseDeny: Object.freeze([]),
});

const level = (value, fallback) => GATE_LEVELS.includes(value) ? value : fallback;
const ceiling = value => CEILINGS.includes(value) ? value : 'high';
const threshold = value => !Number.isSafeInteger(value) || value < 0 ? 0 : Math.min(value, 100000);

export function sanitizePolicy(input) {
  const source = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  const deny = Array.isArray(source.licenseDeny) ? source.licenseDeny : [];
  return {
    installScripts: level(source.installScripts, DEFAULT_POLICY.installScripts),
    typosquat: level(source.typosquat, DEFAULT_POLICY.typosquat),
    typosquatMax: threshold(source.typosquatMax),
    unpinned: level(source.unpinned, DEFAULT_POLICY.unpinned),
    unpinnedMax: threshold(source.unpinnedMax),
    severityCeiling: ceiling(source.severityCeiling ?? DEFAULT_POLICY.severityCeiling),
    licenseDeny: [...new Set(deny.filter(item => typeof item === 'string' && item.trim() && item.length <= 120)
      .map(item => item.trim().toLowerCase()))].sort(compare).slice(0, 200),
  };
}

function activeIndex(model) {
  const nodes = (Array.isArray(model?.nodes) ? model.nodes : []).filter(node => !node.quarantined);
  const ids = new Set(nodes.map(node => node.id));
  const seen = new Set();
  const edges = (Array.isArray(model?.edges) ? model.edges : [])
    .filter(edge => ids.has(edge.from) && ids.has(edge.to))
    .filter(edge => {
      // Node ids can come from SBOM bom-ref strings and may contain '→'.
      // Key the pair losslessly so two distinct edges cannot collapse.
      const key = JSON.stringify([edge.from, edge.to]);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  return { ...indexGraph(nodes, edges), nodes, edges };
}

/* Every minimum-length dependency path from the virtual root to the target,
   enumerated on the shortest-path DAG (each step descends exactly one BFS
   depth), so cycles can never loop and ordering stays deterministic. The
   descent set is first pruned to nodes that can still reach the target, so
   dead branches never multiply: cost is bounded by the graph plus
   cap x depth, not by the count of shortest paths. */
export function exposurePaths(model, targetId, cap = 64) {
  const { byId, outgoing, incoming } = activeIndex(model);
  if (!byId.has(targetId)) return [];
  if (targetId === model.rootId) return [[model.rootId]];
  const { depths } = breadthFirst(model.rootId, outgoing);
  const goal = depths.get(targetId);
  if (goal === undefined) return [];
  const onPath = new Set([targetId]);
  const queue = [targetId];
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i];
    for (const prev of incoming.get(id) ?? []) {
      if (depths.get(prev) === depths.get(id) - 1 && !onPath.has(prev)) {
        onPath.add(prev);
        queue.push(prev);
      }
    }
  }
  const descent = new Map();
  for (const id of onPath) {
    descent.set(id, (outgoing.get(id) ?? [])
      .filter(item => onPath.has(item) && depths.get(item) === depths.get(id) + 1));
  }
  const paths = [];
  const path = [model.rootId];
  const stack = [[model.rootId, 0]];
  while (stack.length && paths.length < cap) {
    const frame = stack.at(-1);
    const id = frame[0];
    const next = descent.get(id)[frame[1]];
    if (next === undefined) {
      stack.pop();
      path.pop();
      continue;
    }
    frame[1]++;
    if (next === targetId) paths.push([...path, next]);
    else {
      path.push(next);
      stack.push([next, 0]);
    }
  }
  return paths;
}

/* Reverse-dependency view of one component: direct dependents are the
   immediate incoming neighbors, transitive dependents everything that can
   reach it at all (excluding the virtual root and unresolved records). */
export function dependents(model, targetId) {
  const { byId, incoming } = activeIndex(model);
  const name = id => byId.get(id)?.name ?? String(id);
  const direct = [...(incoming.get(targetId) ?? [])].filter(id => id !== model.rootId).sort(compare);
  const transitive = [...breadthFirst(targetId, incoming).depths.keys()]
    .filter(id => id !== targetId && id !== model.rootId && !byId.get(id)?.unresolved).sort(compare);
  return {
    direct: direct.map(id => ({ id, name: name(id) })),
    transitive: transitive.map(id => ({ id, name: name(id) })),
  };
}

/* Full what-if report for quarantining one component: which dependents lose
   it directly, which lose it transitively, which become unreachable orphans,
   and the exact score and finding deltas. Runs the real analyzer twice so
   the verdict is measured, not estimated. */
export function blastRadius(model, targetId, changes) {
  const nodes = Array.isArray(model?.nodes) ? model.nodes : [];
  const target = nodes.find(node => node.id === targetId);
  if (!target) throw new Error('Unknown component.');
  if (target.root || targetId === model.rootId) throw new Error('The root component cannot be quarantined.');
  if (target.quarantined) throw new Error('This component is already quarantined.');
  const staged = new Map(changes ?? []);
  staged.set(targetId, { action: 'quarantine' });
  const base = analyze(model);
  const simulated = analyze(simulate(model, staged));
  const { byId } = activeIndex(model);
  const name = id => byId.get(id)?.name ?? String(id);
  const { direct, transitive } = dependents(model, targetId);
  const reachableBefore = new Set([...base.depths.keys()]);
  const orphaned = [...reachableBefore]
    .filter(id => id !== targetId && id !== model.rootId && !simulated.depths.has(id) && byId.has(id))
    .sort(compare);
  const contributing = new Set(simulated.findings.filter(item => item.points > 0)
    .map(item => `${item.ruleId}:${item.nodeId}`));
  const cleared = base.findings.filter(item => item.points > 0 && !contributing.has(`${item.ruleId}:${item.nodeId}`));
  return {
    nodeId: targetId,
    name: target.name,
    version: target.version ?? '',
    paths: exposurePaths(model, targetId).map(path => path.map(id => ({ id, name: name(id) }))),
    directDependents: direct,
    transitiveDependents: transitive,
    orphaned: orphaned.map(id => ({ id, name: name(id) })),
    score: { before: base.score, after: simulated.score, delta: base.score - simulated.score },
    findings: { before: base.findings.length, after: simulated.findings.length, cleared: cleared.length },
    cleared: cleared.map(item => ({ ruleId: item.ruleId, nodeId: item.nodeId, severity: item.severity, title: item.title })),
    simulated,
  };
}

/* Preview an arbitrary change set without adopting it: returns the simulated
   analysis plus metric deltas against the current model. */
export function whatIf(model, changes) {
  const base = analyze(model);
  const simulated = analyze(simulate(model, changes));
  return {
    base, simulated,
    delta: {
      score: simulated.score - base.score,
      findings: simulated.findings.length - base.findings.length,
      affected: (simulated.metrics?.affected ?? 0) - (base.metrics?.affected ?? 0),
      reachable: (simulated.metrics?.reachable ?? 0) - (base.metrics?.reachable ?? 0),
    },
  };
}

/* Deterministic gate: reachable findings only, worst triggered level wins.
   License deny entries match recorded SPDX ids or names case-insensitively;
   formats that record no license data report zero coverage instead of
   pretending to have checked. */
export function policyGate(analysis, policyInput) {
  const policy = sanitizePolicy(policyInput);
  const findings = (Array.isArray(analysis?.findings) ? analysis.findings : []).filter(item => item.reachable);
  const count = rules => findings.filter(item => rules.has(item.ruleId)).length;
  const checks = [];

  const hooks = count(HOOK_RULES);
  checks.push({
    id: 'install-scripts', label: 'Install lifecycle hooks', level: policy.installScripts,
    triggered: hooks > 0, count: hooks,
    detail: hooks ? `${hooks} reachable hook finding${hooks === 1 ? '' : 's'} (SG003-SG006)` : 'no reachable hook findings',
  });

  const typos = count(TYPO_RULES);
  checks.push({
    id: 'typosquat', label: 'Lookalike and confusable names', level: policy.typosquat,
    triggered: typos > policy.typosquatMax, count: typos, threshold: policy.typosquatMax,
    detail: `${typos} reachable lookalike finding${typos === 1 ? '' : 's'} against a ceiling of ${policy.typosquatMax}`,
  });

  const unpinned = count(UNPINNED_RULES);
  checks.push({
    id: 'unpinned', label: 'Unpinned declarations', level: policy.unpinned,
    triggered: unpinned > policy.unpinnedMax, count: unpinned, threshold: policy.unpinnedMax,
    detail: `${unpinned} reachable unpinned finding${unpinned === 1 ? '' : 's'} against a ceiling of ${policy.unpinnedMax}`,
  });

  const rank = policy.severityCeiling === 'off' ? -1 : SEV_RANK[policy.severityCeiling];
  const severe = findings.filter(item => (SEV_RANK[item.severity] ?? 9) <= rank);
  checks.push({
    id: 'severity-ceiling', label: 'Severity ceiling', level: 'block',
    triggered: severe.length > 0, count: severe.length, ceiling: policy.severityCeiling,
    detail: policy.severityCeiling === 'off' ? 'ceiling disabled'
      : severe.length ? `${severe.length} finding${severe.length === 1 ? '' : 's'} at or above ${policy.severityCeiling}`
        : `nothing at or above ${policy.severityCeiling}`,
  });

  const deny = new Set(policy.licenseDeny);
  /* SPDX expressions are recorded verbatim; a deny entry hits the whole
     string or any license token inside one. Operators only split when
     space-separated so hyphenated ids like gpl-3.0-or-later stay whole. */
  /* Parens and space runs collapse together: turning a run of '(' into a
     run of spaces would re-create the quadratic split this split avoids. */
  const licenseTokens = value => String(value).toLowerCase()
    .replace(/[()\s]+/g, ' ')
    .split(/\s+(?:and|or|with)\s+/i).map(part => part.trim()).filter(Boolean);
  const licensed = (Array.isArray(analysis?.model?.nodes) ? analysis.model.nodes : [])
    .filter(node => !node.root && !node.unresolved && !node.quarantined &&
      Array.isArray(node.licenses) && node.licenses.length);
  const matches = licensed
    .flatMap(node => node.licenses
      .filter(value => deny.has(String(value).toLowerCase())
        || licenseTokens(value).some(token => deny.has(token)))
      .map(value => ({ nodeId: node.id, name: node.name, license: value })))
    .sort((a, b) => compare(a.nodeId, b.nodeId) || compare(a.license, b.license));
  checks.push({
    id: 'license-deny', label: 'License denylist', level: 'block',
    triggered: matches.length > 0, count: matches.length, matches,
    coverage: { recorded: licensed.length, denied: policy.licenseDeny.length },
    detail: !policy.licenseDeny.length ? 'denylist empty'
      : licensed.length ? `${matches.length} denied license match${matches.length === 1 ? '' : 'es'}`
        : 'no license metadata recorded in this input',
  });

  const verdict = checks.some(check => check.triggered && check.level === 'block') ? 'BLOCK'
    : checks.some(check => check.triggered && check.level === 'warn') ? 'WARN' : 'PASS';
  return { verdict, checks, scope: 'reachable findings only', policy };
}
