"""Synthetic test cases benchmark

Evaluates the code review system on 5 hand-crafted test cases with known expected findings.
"""

from pathlib import Path
from typing import Optional

from agents import Agent, Runner
from pydantic import BaseModel, Field

from code_review.pipeline import review_code


class MatchedFinding(BaseModel):
    expected: str = Field(description="the expected finding text")
    matched: bool = Field(description="true if the expected finding is present, else false")
    actual_finding: Optional[str] = Field(default=None, description="the matching text from report (if matched)")


class EvaluationResult(BaseModel):
    matched_findings: list[MatchedFinding]
    total_expected: int = Field(description="Total number of expected findings from ground truth")
    total_actual: int = Field(description="Count of distinct issues in the report's summary section")

    def model_post_init(self, __context):
        # Calculate matches from the list
        matches = sum(1 for mf in self.matched_findings if mf.matched)

        # Check for duplicate actual findings
        actual_findings_used = [
            mf.actual_finding for mf in self.matched_findings
            if mf.matched and mf.actual_finding
        ]
        unique_actuals = len(set(actual_findings_used))

        if matches > unique_actuals:
            print(f"ERROR: {matches} matches but only {unique_actuals} unique actual findings used!")
            print("The judge matched the same actual finding multiple times.")

        if matches > self.total_actual:
            print(f"WARNING: Matches ({matches}) > Total Actual ({self.total_actual})")


JUDGE_INSTRUCTIONS = """You are an evaluation judge for code review systems comparing expected findings (ground truth) against actual findings.

CRITICAL MATCHING RULES:
1. Each actual finding can match AT MOST ONE expected finding
2. Each expected finding can match AT MOST ONE actual finding
3. Once an actual finding is matched, it CANNOT be used again
4. Only match within same category (bugs ≠ test gaps)

PROCESS:
1. Count total_actual from "Total Distinct Issues: X" in report
2. For EACH expected finding:
   - Find the BEST matching actual finding that hasn't been used yet
   - If good match exists: mark as matched=True, record which actual finding
   - If no match: mark as matched=False
   - NEVER reuse an actual finding for multiple expected findings

A match means the same type of issue was identified, even if worded differently.
"""


async def evaluate_report(report, ground_truth_content):
    """Evaluate a code review report against ground truth

    Args:
        report: The markdown report from review_code
        ground_truth_content: JSON string with expected findings

    Returns:
        dict with recall, precision, f1, matches, total_expected, total_actual, details
    """
    judge_agent = Agent(
        name="Evaluation Judge",
        instructions=JUDGE_INSTRUCTIONS,
        model="gpt-5.1",
        output_type=EvaluationResult
    )

    prompt = f"""
GROUND TRUTH (expected findings):
{ground_truth_content}

ACTUAL REPORT (what the system found):
{report}

For each expected finding, determine if it matches any actual finding.
Output matched_findings list, total_expected, and total_actual.
"""

    result = await Runner.run(judge_agent, prompt)
    eval_result = result.final_output

    # Calculate matches from the actual data - don't trust LLM counting
    matches = sum(1 for mf in eval_result.matched_findings if mf.matched)

    # Calculate metrics
    recall = matches / eval_result.total_expected if eval_result.total_expected > 0 else 0
    precision = matches / eval_result.total_actual if eval_result.total_actual > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "recall": recall,
        "precision": precision,
        "f1": f1,
        "matches": matches,
        "total_expected": eval_result.total_expected,
        "total_actual": eval_result.total_actual,
        "details": eval_result.matched_findings
    }


async def run_all_tests():
    """Run all 5 synthetic test cases

    Returns:
        list of test results
    """
    test_cases = [
        "01_sql_injection",
        "02_logic_bug",
        "03_code_quality",
        "04_multi_file_security",
        "05_multi_file_mixed"
    ]

    test_dir = Path("test-cases")
    results = []

    for test_name in test_cases:
        print(f"\n{'='*60}")
        print(f"TESTING: {test_name}")
        print('='*60)

        # Load files
        diff_file = test_dir / f"{test_name}.diff"
        diff_content = diff_file.read_text()
        expected_file = test_dir / f"{test_name}_expected.json"
        ground_truth_content = expected_file.read_text()

        # Run review
        report = await review_code(diff_content, save_output=False)

        # Evaluate
        eval_result = await evaluate_report(report, ground_truth_content)

        # Print detailed judge output
        print("\n" + "="*60)
        print("JUDGE OUTPUT:")
        print("="*60)
        print(f"total_expected: {eval_result['total_expected']}")
        print(f"total_actual: {eval_result['total_actual']}")
        print(f"matches: {eval_result['matches']}")
        print(f"\nmatched_findings:")
        for mf in eval_result['details']:
            print(f"\n  Expected: {mf.expected}")
            print(f"  Matched: {mf.matched}")
            if mf.actual_finding:
                print(f"  Actual: {mf.actual_finding[:100]}...")

        # Store results
        results.append({
            'test_name': test_name,
            'recall': eval_result['recall'],
            'precision': eval_result['precision'],
            'f1': eval_result['f1'],
            'passed': eval_result['recall'] >= 0.80 and
                     eval_result['precision'] >= 0.85 and
                     eval_result['f1'] >= 0.82
        })

        # Print calculated metrics
        print("\n" + "="*60)
        print("CALCULATED METRICS:")
        print("="*60)
        print(f"Recall: {eval_result['recall']:.2f}")
        print(f"Precision: {eval_result['precision']:.2f}")
        print(f"F1 Score: {eval_result['f1']:.2f}")
        print(f"Status: {'✓ PASSED' if results[-1]['passed'] else '✗ FAILED'}")

    # Print overall summary
    print(f"\n\n{'='*60}")
    print("OVERALL SUMMARY")
    print('='*60)
    for result in results:
        status = '✓' if result['passed'] else '✗'
        print(f"{status} {result['test_name']}: R={result['recall']:.2f} P={result['precision']:.2f} F1={result['f1']:.2f}")

    passed = sum(1 for r in results if r['passed'])
    print(f"\nPassed: {passed}/{len(results)}")

    return results


if __name__ == "__main__":
    import asyncio

    print("Running synthetic benchmark on 5 test cases...")
    results = asyncio.run(run_all_tests())
