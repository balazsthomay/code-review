"""Main code review pipeline

Orchestrates the multi-agent review process with RAG enhancement.
"""

import os
import asyncio
from datetime import datetime

from agents import Agent, Runner, ModelSettings, trace, FileSearchTool

from code_review.agents import (
    CODE_ANALYZER_INSTRUCTIONS,
    SECURITY_INSTRUCTIONS,
    BEST_PRACTICES_INSTRUCTIONS,
    TEST_COVERAGE_INSTRUCTIONS,
    aggregator,
)
from code_review.schemas import (
    CodeAnalyzerOutput,
    SecurityOutput,
    BestPracticesOutput,
    TestCoverageOutput,
)
from code_review.rag import (
    get_relevant_security_patterns,
    get_relevant_best_practices_patterns,
    get_relevant_python_gotchas,
    get_relevant_code_review_patterns,
    get_relevant_refactoring_patterns,
)


async def run_all_agents(diff, vector_store_id=None):
    """Run all 4 review agents in parallel with RAG-enhanced context

    Args:
        diff: The code diff to review
        vector_store_id: Optional OpenAI vector store ID for codebase context

    Returns:
        Tuple of (code_result, security_result, best_practices_result, test_coverage_result)
    """
    # Get RAG context for all agents
    # INCREASED n_results from 5 to 15 for security patterns to capture more injection patterns
    security_patterns = get_relevant_security_patterns(diff, n_results=15)
    best_practices_patterns = get_relevant_best_practices_patterns(diff, n_results=5)
    python_gotchas = get_relevant_python_gotchas(diff, n_results=3)
    code_review_patterns = get_relevant_code_review_patterns(diff, n_results=3)
    refactoring_patterns = get_relevant_refactoring_patterns(diff, n_results=5)

    # Prepare FileSearchTool if vector store ID provided
    file_search_tool = None
    if vector_store_id:
        file_search_tool = FileSearchTool(max_num_results=5, vector_store_ids=[vector_store_id])

    # Create RAG-enhanced Code Analyzer agent
    enhanced_code_analyzer_instructions = f"""{CODE_ANALYZER_INSTRUCTIONS}

RELEVANT PYTHON GOTCHAS TO CHECK:
{python_gotchas}

RELEVANT CODE REVIEW PATTERNS TO CHECK:
{code_review_patterns}

RELEVANT REFACTORING PATTERNS TO CHECK (Multi-File Changes):
{refactoring_patterns}"""

    # Create RAG-enhanced security agent
    enhanced_security_instructions = f"""{SECURITY_INSTRUCTIONS}

RELEVANT SECURITY PATTERNS TO CHECK:
{security_patterns}"""

    # Create RAG-enhanced best practices agent
    enhanced_best_practices_instructions = f"""{BEST_PRACTICES_INSTRUCTIONS}

RELEVANT BEST PRACTICES PATTERNS TO CHECK:
{best_practices_patterns}"""

    code_analyzer = Agent(
        name="Code Analyzer",
        instructions=enhanced_code_analyzer_instructions,
        model="gpt-4.1-mini",
        model_settings=ModelSettings(
            temperature=0.6,
            max_tokens=4000,
        ),
        tools=[file_search_tool] if file_search_tool else [],
        output_type=CodeAnalyzerOutput
    )

    security_agent = Agent(
        name="Security Agent",
        instructions=enhanced_security_instructions,
        model="gpt-4.1-mini",
        model_settings=ModelSettings(
            temperature=0.6,
            max_tokens=4000,
        ),
        output_type=SecurityOutput
    )

    best_practices_agent = Agent(
        name="Best Practices Agent",
        instructions=enhanced_best_practices_instructions,
        model="gpt-4.1-mini",
        model_settings=ModelSettings(
            temperature=0.6,
            max_tokens=4000,
        ),
        output_type=BestPracticesOutput
    )

    # Create Test Coverage agent with FileSearchTool if available
    test_coverage_agent = Agent(
        name="Test Coverage Agent",
        instructions=TEST_COVERAGE_INSTRUCTIONS,
        model="gpt-4.1-mini",
        model_settings=ModelSettings(
            temperature=0.6,
            max_tokens=4000,
        ),
        tools=[file_search_tool] if file_search_tool else [],
        output_type=TestCoverageOutput
    )

    # Run all agents in parallel
    results = await asyncio.gather(
        Runner.run(code_analyzer, diff),
        Runner.run(security_agent, diff),
        Runner.run(best_practices_agent, diff),
        Runner.run(test_coverage_agent, diff)
    )
    return results


def organize_findings(code_result, security_result, best_practices_result, test_coverage_result):
    """Organize all findings by file

    Args:
        code_result: CodeAnalyzer output
        security_result: SecurityAgent output
        best_practices_result: BestPracticesAgent output
        test_coverage_result: TestCoverageAgent output

    Returns:
        dict: {
            "file.py": [Finding, Finding, TestGap, ...]
        }
    """
    organized = {}
    for result in [code_result, security_result, best_practices_result, test_coverage_result]:
        for finding in result.final_output.findings:
            file = finding.file
            if file not in organized:
                organized[file] = []
            organized[file].append(finding)

    return organized


async def review_code(diff: str, save_output: bool = True, min_severity: int = 5, vector_store_id: str | None = None) -> str:
    """Complete code review pipeline

    Args:
        diff: The code diff to review
        save_output: Whether to save the report to a file (default: True)
        min_severity: Minimum severity threshold (1-10). Findings below this are filtered out. (default: 5)
        vector_store_id: Optional OpenAI vector store ID for codebase context

    Returns:
        Markdown-formatted code review report
    """
    with trace("Multi-Agent Code Review"):
        results = await run_all_agents(diff, vector_store_id=vector_store_id)
        code_result, security_result, best_practices_result, test_coverage_result = results

        # Filter findings by severity threshold
        def filter_by_severity(result):
            filtered_findings = [
                finding for finding in result.final_output.findings
                if getattr(finding, 'severity', getattr(finding, 'priority', 0)) >= min_severity
            ]
            result.final_output.findings = filtered_findings
            return result

        code_result = filter_by_severity(code_result)
        security_result = filter_by_severity(security_result)
        best_practices_result = filter_by_severity(best_practices_result)
        test_coverage_result = filter_by_severity(test_coverage_result)

        organized = organize_findings(code_result, security_result, best_practices_result, test_coverage_result)

        # If all findings were filtered out, return early with a clean report
        if not any(organized.values()):
            clean_report = "No issues found meeting severity threshold.\n"
            print(clean_report)
            return clean_report

        result = await Runner.run(aggregator, f"Aggregate these findings into a structured report:\n\n{organized}")
        report = result.final_output

        print(report)

        if save_output:
            os.makedirs("user-data", exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"user-data/code_review_{timestamp}.md"
            with open(filepath, "w") as f:
                f.write(report)
            print(f"Report saved to {filepath}")

        return report