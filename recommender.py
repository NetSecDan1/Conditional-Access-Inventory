"""Sort and group gaps for the report."""

from typing import Dict, List

from models import Gap

_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


class Recommender:

    def sorted_gaps(self, gaps: List[Gap]) -> List[Gap]:
        return sorted(gaps, key=lambda g: (_ORDER.get(g.severity, 9), g.category, g.title))

    def by_severity(self, gaps: List[Gap]) -> Dict[str, List[Gap]]:
        out: Dict[str, List[Gap]] = {"Critical": [], "High": [], "Medium": [], "Low": []}
        for gap in self.sorted_gaps(gaps):
            out.setdefault(gap.severity, []).append(gap)
        return out
