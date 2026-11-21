export const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;

export function indexGraph(nodes, edges) {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const outgoing = new Map(nodes.map(node => [node.id, []]));
  const incoming = new Map(nodes.map(node => [node.id, []]));
  for (const { from, to } of edges) {
    if (!byId.has(from) || !byId.has(to)) throw new Error('Invalid graph endpoint.');
    outgoing.get(from).push(to);
    incoming.get(to).push(from);
  }
  for (const list of [...outgoing.values(), ...incoming.values()]) list.sort(compare);
  return { byId, outgoing, incoming };
}

export function breadthFirst(start, adjacency) {
  const predecessor = new Map([[start, null]]);
  const depths = new Map([[start, 0]]);
  const queue = [start];
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i];
    for (const next of adjacency.get(id) ?? []) {
      if (predecessor.has(next)) continue;
      predecessor.set(next, id);
      depths.set(next, depths.get(id) + 1);
      queue.push(next);
    }
  }
  return { predecessor, depths };
}

export function trace(id, predecessor) {
  if (!predecessor.has(id)) return null;
  const path = [];
  const seen = new Set();
  for (let current = id; current != null && !seen.has(current); current = predecessor.get(current)) {
    seen.add(current);
    path.push(current);
  }
  return path.reverse();
}

// Source strongly connected components cover cycles without pretending to know an entry point.
export function inferredEntries(nodes, edges) {
  const { outgoing, incoming } = indexGraph(nodes, edges);
  const finished = [];
  const visited = new Set();
  for (const start of outgoing.keys()) {
    if (visited.has(start)) continue;
    visited.add(start);
    const stack = [[start, 0]];
    while (stack.length) {
      const frame = stack.at(-1);
      const next = outgoing.get(frame[0])[frame[1]++];
      if (next === undefined) finished.push(stack.pop()[0]);
      else if (!visited.has(next)) {
        visited.add(next);
        stack.push([next, 0]);
      }
    }
  }
  const membership = new Map();
  const components = [];
  for (const id of finished.reverse()) {
    if (membership.has(id)) continue;
    const index = components.length;
    const queue = [id];
    membership.set(id, index);
    for (let i = 0; i < queue.length; i++) {
      for (const next of incoming.get(queue[i])) {
        if (membership.has(next)) continue;
        membership.set(next, index);
        queue.push(next);
      }
    }
    components.push(queue);
  }
  const downstream = new Set();
  for (const { from, to } of edges) {
    if (membership.get(from) !== membership.get(to)) downstream.add(membership.get(to));
  }
  return components.flatMap((ids, index) => downstream.has(index) ? [] : ids).sort(compare);
}
