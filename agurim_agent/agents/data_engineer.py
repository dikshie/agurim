"""Agurim Data Engineer Agent: Query, parameter tuning, and HHH extraction."""

from __future__ import annotations

import os

from google.adk.agents import LlmAgent

from agurim_agent.tools import (
    list_datasets_and_ranges,
    query_agurim_flow_data,
)

DEFAULT_MODEL = os.environ.get("AGURIM_AGENT_MODEL", "gemini-2.5-flash")

data_engineer_agent = LlmAgent(
    name="AgurimDataEngineer",
    model=DEFAULT_MODEL,
    description=(
        "Queries Agurim flow data to extract time-series, Hierarchical Heavy Hitters (HHH), "
        "and traffic metrics for specific datasets, time ranges, and protocols."
    ),
    instruction="""You are the Agurim Data Engineer Specialist.
Your sole job is to query and extract Agurim flow data accurately and efficiently.
1. Convert human time descriptions into exact start_time, end_time, or duration timestamps.
2. Select the optimal aggregation interval:
   - 300s (5-minute) for fine-grained incident and burst inspection.
   - 3600s (1-hour) for daily trends.
   - 86400s (1-day) for monthly or yearly views.
3. Select appropriate criteria ('byte' or 'packet').
4. Execute 'query_agurim_flow_data' and extract top flow labels, percentages, and data point rates.
5. Return a clean, structured summary of the flows found, their volume, and peak timestamps.
""",
    tools=[list_datasets_and_ranges, query_agurim_flow_data],
)
