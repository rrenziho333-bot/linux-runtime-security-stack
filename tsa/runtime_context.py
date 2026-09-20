"""Narrow read-only advisories and a separate budget for weak indicators."""

FIELDS = {'process', 'executable', 'parent', 'command', 'file', 'uid', 'container_id'}
REQUIRED = {'executable', 'parent', 'command', 'file', 'uid', 'container_id'}


def _advisories(config):
    policies = config.get('context_advisories', [])
    if not isinstance(policies, list):
        raise ValueError('context_advisories must be a list')
    for policy in policies:
        match = policy.get('match', {}) if isinstance(policy, dict) else {}
        if (not isinstance(match, dict) or not REQUIRED <= set(match) <= FIELDS
                or not isinstance(policy.get('rule'), str) or not policy['rule'].strip()
                or not isinstance(policy.get('reason'), str) or not policy['reason'].strip()
                or any(not isinstance(values, list) or not values
                       or any(type(v) not in (str, int) for v in values) for values in match.values())
                or any(type(v) is not str for key, values in match.items() if key != 'uid' for v in values)
                or match.get('container_id') != ['host'] or match.get('uid') != [0]
                or any(not path.startswith('/') or '*' in path for path in match.get('executable', []))):
            raise ValueError('Invalid read-only context advisory; exact host/root context is required')
    return policies


def advisory_reason(rule, evidence, config):
    for policy in _advisories(config):
        match = policy['match']
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


def _budget(config):
    budget = config.get('signal_budget')
    if budget is None:
        return None
    if (not isinstance(budget, dict) or type(budget.get('max_points')) is not int
            or not 1 <= budget['max_points'] <= 100 or not isinstance(budget.get('rules'), list)
            or not budget['rules'] or any(not isinstance(rule, str) or not rule.strip() for rule in budget['rules'])
            or len(set(budget['rules'])) != len(budget['rules'])
            or not isinstance(budget.get('reason'), str) or not budget['reason'].strip()):
        raise ValueError('Invalid weak-indicator budget')
    return budget


def validate_runtime_config(config):
    """Reject misspelled or unsafe exceptions before processing any events."""
    policies = _advisories(config)
    budget = _budget(config)
    specific = config.get('specific_rules', {}) or {}
    references = [policy['rule'] for policy in policies] + (budget['rules'] if budget else [])
    for rule in references:
        if rule not in specific:
            raise ValueError(f'Context/budget references an unconfigured scoring rule: {rule}')
        policy = specific[rule]
        if isinstance(policy, dict) and (policy.get('test_only') or not policy.get('enabled', True)):
            raise ValueError(f'Context/budget must reference an enabled, non-test scoring rule: {rule}')
    if (policies or budget) and config.get('aggregation') != 'peak_per_rule':
        raise ValueError('Context/budget requires peak_per_rule aggregation')


def score_effect(previous, contribution, before, after):
    """Explain the marginal deduction, not the historical sum of all alerts."""
    increase = max(0, contribution - previous)
    deducted = max(0, min(100, after) - min(100, before))
    causes = []
    if not increase:
        causes.append('same_rule_active')
    if after - before < increase:
        causes.append('weak_signal_budget')
    if deducted < max(0, after - before):
        causes.append('runtime_score_floor')
    labels = {'same_rule_active': '同规则有效风险已覆盖本次风险值，不叠加扣分',
              'weak_signal_budget': '弱线索合计预算限制了本次新增扣分',
              'runtime_score_floor': '运行时评分最低为 0，超出部分不再扣分'}
    return {'risk_before': before, 'risk_after': after, 'deducted_points': deducted,
            'causes': causes, 'explanation': '；'.join(labels[c] for c in causes) or '新增有效规则风险'}


def apply_signal_budget(items, config):
    """Keep every rule visible, with a deterministic current contribution."""
    budget = _budget(config)
    if budget is None:
        return items
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
