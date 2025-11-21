"""BugsInPy benchmark

Evaluates the code review system on real Python bugs from production projects.
Dataset: 502 bugs from 17 projects (scrapy, ansible, keras, pandas, etc.)
"""

from pathlib import Path

from agents import Agent, Runner, ModelSettings, trace
from agents.extensions.models.litellm_model import LitellmModel
from pydantic import BaseModel, Field
import os

from code_review.pipeline import review_code
from code_review.benchmarks.utils import (
    reverse_diff,
    parse_changed_locations,
    parse_flagged_locations,
    calculate_location_metrics,
)


class LLMRelevance(BaseModel):
    """LLM's assessment of how relevant the review findings are to the actual fix"""
    relevance_score: float = Field(description="0.0-1.0: How well the review findings align with the actual fix")
    explanation: str = Field(description="Brief explanation of the score")


LLM_JUDGE_INSTRUCTIONS = """You are evaluating the semantic relevance of code review findings to an actual bug fix.

CRITICAL: Output ONLY valid JSON matching the specified schema. Do NOT wrap your response in markdown code fences or backticks.

Given:
1. ACTUAL FIX PATCH: The changes that were made to fix bugs
2. CODE REVIEW REPORT: What the review system found

Rate the relevance (0.0 to 1.0) of the review findings:
- 1.0: Findings directly identify the bugs that were fixed
- 0.7-0.9: Findings flag related issues that would lead to discovering the bugs
- 0.4-0.6: Findings flag the general area but miss specific bugs
- 0.1-0.3: Findings are tangentially related
- 0.0: No relevant findings

Be objective and strict in your assessment."""


async def evaluate_hybrid(report, bug_patch):
    """Hybrid evaluation: Location metrics (automated) + LLM relevance (semantic)

    Stage 1: Calculate automated location overlap
    Stage 2: If file_recall > 0, use LLM to judge semantic relevance

    Args:
        report: The markdown report from review_code
        bug_patch: The patch showing the actual bug fix

    Returns:
        dict with file_recall, line_precision, line_recall, llm_relevance, composite_score
    """
    # Stage 1: Automated location metrics
    actual_locations = parse_changed_locations(bug_patch)
    flagged_locations = parse_flagged_locations(report)
    location_metrics = calculate_location_metrics(actual_locations, flagged_locations)

    # Stage 2: LLM relevance (only if there's file overlap)
    llm_relevance = 0.0
    if location_metrics['file_recall'] > 0:
        openrouter_api_key = os.getenv('OPENROUTER_API_KEY')
        grok_model = LitellmModel(model="openrouter/x-ai/grok-4.1-fast", api_key=openrouter_api_key)

        llm_judge = Agent(
            name="Relevance Judge",
            instructions=LLM_JUDGE_INSTRUCTIONS,
            model=grok_model,
            model_settings=ModelSettings(
                temperature=0.6,
                extra_args={"reasoning": {"enabled": True}}
            ),
            output_type=LLMRelevance
        )

        prompt = f"""
ACTUAL FIX PATCH:
{bug_patch}

CODE REVIEW REPORT:
{report}

Rate the semantic relevance of the review findings to the actual fix.
"""
        with trace("LLM Judge"):
            result = await Runner.run(llm_judge, prompt)
            llm_relevance = result.final_output.relevance_score

    # Composite score: average of line recall and LLM relevance
    composite_score = (location_metrics['line_recall'] + llm_relevance) / 2

    return {
        'file_recall': location_metrics['file_recall'],
        'line_precision': location_metrics['line_precision'],
        'line_recall': location_metrics['line_recall'],
        'llm_relevance': llm_relevance,
        'composite_score': composite_score
    }


async def test_bugsinpy_with_miss_analysis(bugs_to_test):
    """Test multiple BugsInPy bugs with detailed miss analysis

    Shows what the agents caught vs. what they missed.

    Args:
        bugs_to_test: list of (project, bug_id) tuples

    Returns:
        list of result dicts
    """
    results = []

    for project, bug_id in bugs_to_test:
        print(f"\n{'='*60}")
        print(f"TESTING: {project} bug {bug_id}")
        print('='*60)

        try:
            # Load bug patch
            bug_patch_path = Path(f"BugsInPy/projects/{project}/bugs/{bug_id}/bug_patch.txt")
            bug_patch = bug_patch_path.read_text()

            print("\nACTUAL FIX (first 500 chars):")
            print(bug_patch[:500])
            print("..." if len(bug_patch) > 500 else "")

            # Reverse diff
            reversed_diff = reverse_diff(bug_patch)

            # Run review
            report = await review_code(reversed_diff, save_output=False)

            # Hybrid evaluation
            eval_result = await evaluate_hybrid(report, bug_patch)

            # Parse locations to show what was missed
            actual_locations = parse_changed_locations(bug_patch)
            flagged_locations = parse_flagged_locations(report)

            # Find missed files
            missed_files = actual_locations['files'] - flagged_locations['files']

            # Find missed line ranges
            missed_lines = {}
            for file in actual_locations['files']:
                actual_lines = actual_locations['lines'].get(file, set())
                flagged_lines_in_file = flagged_locations['lines'].get(file, set())

                # Lines that weren't caught (no flagged line within 5 lines)
                uncaught = []
                for actual_line in actual_lines:
                    if not any(abs(actual_line - flagged_line) <= 5 for flagged_line in flagged_lines_in_file):
                        uncaught.append(actual_line)

                if uncaught:
                    missed_lines[file] = sorted(uncaught)

            # Store result
            result = {
                'project': project,
                'bug_id': bug_id,
                'file_recall': eval_result['file_recall'],
                'line_precision': eval_result['line_precision'],
                'line_recall': eval_result['line_recall'],
                'llm_relevance': eval_result['llm_relevance'],
                'composite_score': eval_result['composite_score'],
                'passed': eval_result['composite_score'] >= 0.60,
                'missed_files': list(missed_files),
                'missed_lines': missed_lines
            }
            results.append(result)

            # Print metrics
            print(f"\n📍 LOCATION METRICS:")
            print(f"  File Recall: {eval_result['file_recall']:.0%}")
            print(f"  Line Precision: {eval_result['line_precision']:.0%}")
            print(f"  Line Recall: {eval_result['line_recall']:.0%}")
            print(f"\n🤖 LLM RELEVANCE: {eval_result['llm_relevance']:.0%}")
            print(f"🎯 COMPOSITE: {eval_result['composite_score']:.0%}")

            # Show what was missed
            if missed_files:
                print(f"\n❌ MISSED FILES: {', '.join(missed_files)}")

            if missed_lines:
                print(f"\n❌ MISSED LINES:")
                for file, lines in missed_lines.items():
                    line_ranges = []
                    start = lines[0]
                    end = start
                    for i in range(1, len(lines)):
                        if lines[i] == end + 1:
                            end = lines[i]
                        else:
                            line_ranges.append(f"{start}-{end}" if start != end else str(start))
                            start = lines[i]
                            end = start
                    line_ranges.append(f"{start}-{end}" if start != end else str(start))
                    print(f"  {file}: lines {', '.join(line_ranges)}")

            print(f"\n{'✓ PASSED' if result['passed'] else '✗ FAILED'}")

        except Exception as e:
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()
            results.append({
                'project': project,
                'bug_id': bug_id,
                'error': str(e),
                'passed': False
            })

    # Print overall summary
    print(f"\n\n{'='*60}")
    print("OVERALL SUMMARY")
    print('='*60)
    for result in results:
        if 'error' in result:
            print(f"✗ {result['project']}/{result['bug_id']}: ERROR")
        else:
            status = '✓' if result['passed'] else '✗'
            missed_info = ""
            if result['missed_files']:
                missed_info += f" | Missed files: {len(result['missed_files'])}"
            if result['missed_lines']:
                total_missed = sum(len(lines) for lines in result['missed_lines'].values())
                missed_info += f" | Missed lines: {total_missed}"

            print(f"{status} {result['project']}/{result['bug_id']}: "
                  f"Composite={result['composite_score']:.0%} "
                  f"(LineRec={result['line_recall']:.0%}, LLM={result['llm_relevance']:.0%})"
                  f"{missed_info}")

    passed = sum(1 for r in results if r.get('passed', False))
    print(f"\nPassed: {passed}/{len(results)} ({passed/len(results):.0%})")

    return results


if __name__ == "__main__":
    import asyncio

    # Example: Test a few diverse bugs
    bugs_to_test = [
        ("scrapy", 2),
        ("ansible", 2),
        ("pytest", 2),
        ("pandas", 3),
        ("keras", 3),
    ]

    print("Running BugsInPy benchmark on 5 sample bugs...")
    results = asyncio.run(test_bugsinpy_with_miss_analysis(bugs_to_test))
