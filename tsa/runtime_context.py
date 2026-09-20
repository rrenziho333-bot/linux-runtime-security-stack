"""Narrow read-only advisories and a separate budget for weak indicators."""

FIELDS = {'process', 'executable', 'parent', 'command', 'file', 'uid', 'container_id'}
REQUIRED = {'executable', 'parent', 'command', 'file', 'uid', 'container_id'}


def advisory_reason(rule, evidence, config):
    policies = config.get('context_advisories', [])
    if not isinstance(policies, list):
        raise ValueError('context_advisories must be a list')
    for policy in policies:
        match = policy.get('match', {}) if isinstance(policy, dict) else {}
        if (not isinstance(match, dict) or not REQUIRED <= set(match) <= FIELDS
                or not policy.get('rule') or not policy.get('reason')
                or any(not isinstance(values, list) or not values
                       or any(type(v) not in (str, int) for v in values) for values in match.values())
                or any(type(v) is not str for key, values in match.items() if key != 'uid' for v in values)
                or match.get('container_id') != ['host'] or match.get('uid') != [0]
                or any(not path.startswith('/') or '*' in path for path in match.get('executable', []))):
            raise ValueError('Invalid read-only context advisory; exact host/root context is required')
        if policy['rule'] != rule:
            continue
        if (evidence.get('is_open_write') is not False
                or evidence.get('syscall') not in ('open', 'openat', 'openat2')
                or type(evidence.get('syscall_result')) is not int or evidence['syscall_result'] < 0):
            continue
        if all(any(type(evidence.get(key)) is type(value) and evidence[key] == value for value in values)
               for key, values in match.items()):
            return policy['reason']
    return None


def apply_signal_budget(items, config):
    """Keep every rule visible, with a deterministic current contribution."""
    budget = config.get('signal_budget')
    if budget is None:
        return items
    if (not isinstance(budget, dict) or type(budget.get('max_points')) is not int
            or not 1 <= budget['max_points'] <= 100 or not isinstance(budget.get('rules'), list)
            or not budget['rules'] or any(not isinstance(rule, str) for rule in budget['rules'])
            or not budget.get('reason')):
        raise ValueError('Invalid weak-indicator budget')
    remaining = budget['max_points']
    result = []
    for item in sorted(items, key=lambda row: (-row.get('rule_points', row['points']), row['rule'])):
        row = dict(item)
        raw = row.get('rule_points', row['points'])
        row.update(rule_points=raw, points=raw)
        if row['rule'] in budget['rules']:
            row['points'] = min(raw, remaining)
            remaining -= row['points']
            row.update(budget_limit=budget['max_points'], budget_reason=budget['reason'])
        result.append(row)
    return result
