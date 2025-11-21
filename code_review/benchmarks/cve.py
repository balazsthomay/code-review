"""CVE benchmark

Evaluates the code review system on real security vulnerabilities.
Dataset: 17 Python CVEs covering 11 CWE types from production projects
(Django, Requests, urllib3, Setuptools, Jinja2, PyYAML, Pillow, Flask, Cryptography)
"""

import json
import os
from datetime import datetime
from pathlib import Path
import re

from agents import Agent, Runner, ModelSettings, trace
from agents.extensions.models.litellm_model import LitellmModel
from pydantic import BaseModel, Field

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


def load_cve_dataset(json_path="cve_dataset.json"):
    """Load curated CVE dataset

    Args:
        json_path: Path to cve_dataset.json (default: "cve_dataset.json")

    Returns:
        list of CVE dicts with metadata
    """
    with open(json_path) as f:
        return json.load(f)


def load_cve_patch(cve_id, patches_dir="cve_patches"):
    """Load patch file for specific CVE

    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-6345")
        patches_dir: Directory containing patch files (default: "cve_patches")

    Returns:
        Patch file contents as string
    """
    patch_path = Path(patches_dir) / f"{cve_id}.patch"
    return patch_path.read_text()


def check_security_agent_flagged(report):
    """Check if Security Agent found anything

    Args:
        report: The markdown report

    Returns:
        bool: True if Security Agent flagged issues
    """
    return "Security" in report and "Found By" in report


def extract_max_severity(report):
    """Extract highest severity from report (1-10 scale)

    Args:
        report: The markdown report

    Returns:
        int: Max severity (0 if no security findings)
    """
    # Parse markdown table for severity column (finds Security findings)
    severities = re.findall(r'\|\s*(\d+)\s*\|.*\|\s*Security\s*\|', report, re.IGNORECASE)
    return max(map(int, severities)) if severities else 0


async def evaluate_hybrid_cve(report, patch, cve_id, cwe_id, cwe_name, cvss_score, severity):
    """Hybrid evaluation for CVEs: Location metrics + LLM relevance + Security detection

    Args:
        report: The markdown report
        patch: The CVE patch file
        cve_id: CVE identifier
        cwe_id: CWE identifier
        cwe_name: CWE name
        cvss_score: CVSS score
        severity: Severity level

    Returns:
        dict with metrics
    """
    # Stage 1: Automated location metrics
    actual_locations = parse_changed_locations(patch)
    flagged_locations = parse_flagged_locations(report)
    location_metrics = calculate_location_metrics(actual_locations, flagged_locations)

    # Stage 2: LLM relevance with CVE context
    llm_relevance = 0.0
    if location_metrics['file_recall'] > 0:
        openrouter_api_key = os.getenv('OPENROUTER_API_KEY')
        grok_model = LitellmModel(model="openrouter/x-ai/grok-4.1-fast", api_key=openrouter_api_key)

        llm_judge_cve_instructions = f"""You are evaluating code review findings against a real CVE.

CRITICAL: Output ONLY valid JSON matching the specified schema. Do NOT wrap your response in markdown code fences or backticks.

Given:
1. CVE ID: {cve_id}
2. CWE Type: {cwe_name} ({cwe_id})
3. CVSS Score: {cvss_score} ({severity})
4. ACTUAL FIX PATCH: The changes that fixed the vulnerability
5. CODE REVIEW REPORT: What our system found

Rate the relevance (0.0 to 1.0) of the review findings:
- 1.0: Findings directly identify the CVE vulnerability type
- 0.7-0.9: Findings flag related security issues that would lead to discovery
- 0.4-0.6: Findings flag the general area but miss specific vulnerability
- 0.1-0.3: Findings are tangentially related
- 0.0: No relevant findings

Special attention:
- Did the Security Agent flag this as a security issue?
- Is the severity appropriate for the CVE?"""

        llm_judge = Agent(
            name="CVE Relevance Judge",
            instructions=llm_judge_cve_instructions,
            model=grok_model,
            model_settings=ModelSettings(
                temperature=0.6,
                extra_args={"reasoning": {"enabled": True}}
            ),
            output_type=LLMRelevance
        )

        prompt = f"""
ACTUAL FIX PATCH:
{patch}

CODE REVIEW REPORT:
{report}

Rate the semantic relevance of the review findings to this CVE.
"""
        with trace("CVE LLM Judge"):
            result = await Runner.run(llm_judge, prompt)
            llm_relevance = result.final_output.relevance_score

    # Stage 3: Security detection check
    security_flagged = check_security_agent_flagged(report)
    severity_from_report = extract_max_severity(report)
    severity_appropriate = abs(severity_from_report - cvss_score) <= 3 if severity_from_report > 0 else False

    # Composite score: average of line recall and LLM relevance
    composite_score = (location_metrics['line_recall'] + llm_relevance) / 2

    return {
        'file_recall': location_metrics['file_recall'],
        'line_precision': location_metrics['line_precision'],
        'line_recall': location_metrics['line_recall'],
        'llm_relevance': llm_relevance,
        'composite_score': composite_score,
        'severity_appropriate': severity_appropriate,
        'security_finding_present': security_flagged
    }


async def test_cve_benchmark(cve_dataset):
    """Test code review system on CVE dataset

    Reuses existing hybrid evaluation with CVE enhancements.

    Args:
        cve_dataset: list of CVE dicts from load_cve_dataset()

    Returns:
        list of result dicts
    """
    results = []

    for cve in cve_dataset:
        print(f"\n{'='*60}")
        print(f"TESTING: {cve['cve_id']} - {cve['cwe_name']}")
        print(f"CVSS: {cve['cvss_score']} | Project: {cve['project']}")
        print('='*60)

        try:
            # Load patch
            patch = load_cve_patch(cve['cve_id'])

            # Reverse diff (show vulnerability introduction)
            reversed_diff = reverse_diff(patch)

            # Run code review
            report = await review_code(reversed_diff, save_output=False)

            # Hybrid evaluation with CVE context
            eval_result = await evaluate_hybrid_cve(
                report, patch,
                cve['cve_id'], cve['cwe_id'], cve['cwe_name'],
                cve['cvss_score'], cve['severity']
            )

            result = {
                'cve_id': cve['cve_id'],
                'cwe_id': cve['cwe_id'],
                'cwe_name': cve['cwe_name'],
                'cvss_score': cve['cvss_score'],
                'file_recall': eval_result['file_recall'],
                'line_recall': eval_result['line_recall'],
                'llm_relevance': eval_result['llm_relevance'],
                'composite_score': eval_result['composite_score'],
                'security_flagged': eval_result['security_finding_present'],
                'severity_appropriate': eval_result['severity_appropriate'],
                'passed': eval_result['composite_score'] >= 0.60
            }
            results.append(result)

            # Print metrics
            print(f"\n📍 Location: FileRec={result['file_recall']:.0%}, LineRec={result['line_recall']:.0%}")
            print(f"🤖 LLM Relevance: {result['llm_relevance']:.0%}")
            print(f"🛡️  Security Agent: {'✓ FLAGGED' if result['security_flagged'] else '✗ MISSED'}")
            print(f"📊 Composite: {result['composite_score']:.0%} - {'✓ PASSED' if result['passed'] else '✗ FAILED'}")

        except Exception as e:
            print(f"\n❌ ERROR: {e}")
            import traceback
            traceback.print_exc()
            results.append({
                'cve_id': cve['cve_id'],
                'error': str(e),
                'passed': False
            })

    # Summary
    print(f"\n\n{'='*60}")
    print("CVE BENCHMARK SUMMARY")
    print('='*60)

    valid_results = [r for r in results if 'error' not in r]
    passed = sum(r['passed'] for r in valid_results)
    security_detected = sum(r['security_flagged'] for r in valid_results)

    print(f"Overall Pass Rate: {passed}/{len(valid_results)} ({passed/len(valid_results):.0%})")
    print(f"Security Agent Detection: {security_detected}/{len(valid_results)} ({security_detected/len(valid_results):.0%})")

    # By CWE type
    print(f"\n📋 Results by CWE Type:")
    cwe_results = {}
    for r in valid_results:
        cwe = r['cwe_name']
        if cwe not in cwe_results:
            cwe_results[cwe] = {'total': 0, 'passed': 0}
        cwe_results[cwe]['total'] += 1
        cwe_results[cwe]['passed'] += r['passed']

    for cwe, stats in sorted(cwe_results.items()):
        print(f"  {cwe}: {stats['passed']}/{stats['total']} passed")

    # Save results
    os.makedirs("user-data", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_path = f"user-data/cve_benchmark_{timestamp}.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Results saved to {results_path}")

    return results


if __name__ == "__main__":
    import asyncio

    print("Running CVE benchmark on all 17 CVEs...")
    cve_dataset = load_cve_dataset()
    print(f"Loaded {len(cve_dataset)} CVEs\n")
    results = asyncio.run(test_cve_benchmark(cve_dataset))
