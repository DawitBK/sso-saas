import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

// Matches DMS's and GMS's tools/generate-test-status.mjs exactly (Directive
// §6.20 - consistent tooling across all three systems) - only the fixed
// resultPath/outputPath/product differ, since SSO has no workspace-root split
// the way DMS/GMS do (this package.json IS the backend's own root).
const resultPath = resolve(import.meta.dirname, '..', 'test-results.json');
const outputPath = resolve(import.meta.dirname, '..', 'docs', 'TEST_STATUS.md');
const product = 'Example Corp Identity Provider';

const result = JSON.parse(readFileSync(resultPath, 'utf8'));
const markdown = `# Automated Test Status\n\n> Generated from Jest JSON by \`npm run test:status\`. CI verifies that this file matches the test run.\n\n| Metric | Result |\n|---|---|\n| Product | ${product} |\n| Test suites | ${result.numPassedTestSuites} passed / ${result.numTotalTestSuites} total |\n| Tests | ${result.numPassedTests} passed / ${result.numTotalTests} total |\n| Failed | ${result.numFailedTests} |\n| Status | ${result.success ? 'PASS' : 'FAIL'} |\n`;
mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, markdown);
