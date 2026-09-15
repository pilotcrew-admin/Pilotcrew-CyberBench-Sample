"""Diagnostic replay coverage; denominators include unevaluated corpus members."""


def replay_metrics(rows, attempted, outcomes, expected):
    def summarize(cases):
        evaluated = [outcomes[row[0]] for row in cases if row[0] in outcomes]
        passed = sum(
            result.get("decision") == expected
            and (expected != "block" or 400 <= int(result.get("status", 0)) <= 499)
            for result in evaluated
        )
        total = len(cases)
        return {
            "total": total,
            "attempted": sum(row[0] in attempted for row in cases),
            "evaluated": len(evaluated),
            "passed": passed,
            "failed": len(evaluated) - passed,
            "not_evaluated": total - len(evaluated),
            "pass_rate": passed / total if total else None,
        }

    result = summarize(rows)
    for label, index in (("by_family", 2), ("by_carrier", 3)):
        result[label] = {
            value: summarize([row for row in rows if row[index] == value])
            for value in sorted({row[index] for row in rows})
        }
    return result
