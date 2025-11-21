"""Pydantic schemas for code review findings"""

from pydantic import BaseModel, Field


class BugFinding(BaseModel):
    title: str = Field(description="Brief name for the bug")
    description: str = Field(description="Detailed explanation")
    severity: int = Field(description="Severity 1-10")
    file: str = Field(description="File path")
    relevant_lines: list[int] = Field(description="Line numbers (max 20 lines per finding)", max_length=20)
    suggested_fix: str = Field(description="Recommended solution")


class VulnerabilityFinding(BaseModel):
    title: str = Field(description="Brief name for the vulnerability")
    description: str = Field(description="Detailed explanation")
    severity: int = Field(description="Severity 1-10")
    file: str = Field(description="File path")
    relevant_lines: list[int] = Field(description="Line numbers (max 20 lines per finding)", max_length=20)
    suggested_fix: str = Field(description="Recommended solution")
    cve_reference: str | None = Field(default=None, description="CVE ID if applicable")


class BestPracticeFinding(BaseModel):
    title: str = Field(description="Brief name for the best practice violation")
    description: str = Field(description="Detailed explanation")
    severity: int = Field(description="Severity 1-10")
    file: str = Field(description="File path")
    relevant_lines: list[int] = Field(description="Line numbers (max 20 lines per finding)", max_length=20)
    suggested_fix: str = Field(description="Recommended solution")


class TestGap(BaseModel):
    function_name: str = Field(description="Name of the function/method lacking tests")
    file: str = Field(description="File containing the untested code")
    lines: list[int] = Field(description="Line numbers of the untested code (max 20 lines)", max_length=20)
    missing_scenarios: list[str] = Field(description="Specific test cases that should be added, e.g., ['edge case: empty input', 'error handling: invalid type']")
    priority: int = Field(description="Priority 1-10, based on code criticality")
    suggested_test_approach: str = Field(description="How to test this (unit test, integration test, etc.)")


class CodeAnalyzerOutput(BaseModel):
    findings: list[BugFinding] = Field(description="Bugs and anti-patterns found")


class SecurityOutput(BaseModel):
    findings: list[VulnerabilityFinding] = Field(description="Security vulnerabilities found")


class BestPracticesOutput(BaseModel):
    findings: list[BestPracticeFinding] = Field(description="Style and best practice violations")


class TestCoverageOutput(BaseModel):
    findings: list[TestGap] = Field(description="Testing gaps found")
