const fs = require('fs');
const path = require('path');

const EVALUATION_ENDPOINT = 'http://localhost:5000/api/evaluate';

async function testFileAction(filePath, tool = 'fs.read', destination = 'local workspace') {
    const resolvedPath = path.isAbsolute(filePath) ? filePath : path.resolve(__dirname, filePath);
    const displayPath = path.relative(__dirname, resolvedPath).replace(/\\/g, '/');

    if (!fs.existsSync(resolvedPath)) {
        console.error(`[ERROR] File not found on disk: ${displayPath}`);
        return null;
    }

    let payload;
    try {
        payload = fs.readFileSync(resolvedPath, 'utf8');
    } catch (err) {
        console.error(`[ERROR] Unable to read file at ${displayPath}: ${err.message}`);
        return null;
    }

    const requestBody = {
        tool,
        path: displayPath,
        payload,
        destination
    };

    try {
        const response = await fetch(EVALUATION_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            console.error(`[ERROR] Gateway returned HTTP ${response.status}: ${response.statusText}`);
            return null;
        }

        const data = await response.json();
        const evaluation = data.evaluation || (data.log ? {
            decision: data.log.decision,
            risk: data.log.risk,
            policy: data.log.policy,
            reasoning: data.log.reasoning
        } : null);

        if (!evaluation) {
            console.error(`[ERROR] Invalid evaluation response format received from gateway.`);
            return null;
        }

        console.log('------------------------------------------------------------');
        console.log(`File:        ${displayPath}`);
        console.log(`Tool:        ${tool}`);
        console.log(`Destination: ${destination}`);
        console.log(`Decision:    ${evaluation.decision}`);
        console.log(`Risk Level:  ${evaluation.risk}`);
        console.log(`Policy:      ${evaluation.policy || 'N/A'}`);
        console.log(`Reasoning:   ${evaluation.reasoning}`);
        console.log('------------------------------------------------------------');

        return evaluation;
    } catch (err) {
        const isOffline = err.message === 'fetch failed' ||
            (err.cause && ['ECONNREFUSED', 'EACCES', 'ENOTFOUND'].includes(err.cause.code)) ||
            ['ECONNREFUSED', 'EACCES', 'ENOTFOUND'].includes(err.code);

        if (isOffline) {
            console.error(`[CONNECTION ERROR] Gateway is unreachable at ${EVALUATION_ENDPOINT}.`);
            console.error('Please verify that the backend server is running via "node server.js".');
        } else {
            console.error(`[REQUEST ERROR] Failed to evaluate file action: ${err.message}`);
        }
        return null;
    }
}

async function runTestSuite() {
    console.log('Starting dynamic local file system security evaluation tests...\n');

    const testCases = [
        {
            file: 'test-workspace/sample_database.yml',
            tool: 'fs.read',
            destination: 'local workspace',
            expected: 'DENY (Secrets stay local)'
        },
        {
            file: 'test-workspace/customer_export.csv',
            tool: 'http.post',
            destination: 'https://analytics-external-sink.io/upload',
            expected: 'REQUIRE_APPROVAL (PII egress review)'
        },
        {
            file: 'test-workspace/README.md',
            tool: 'fs.read',
            destination: 'local workspace',
            expected: 'ALLOW (Workspace read access)'
        },
        {
            file: 'test-workspace/cleanup.sh',
            tool: 'terminal.exec',
            destination: 'local workspace',
            expected: 'DENY (Destructive command prevention)'
        }
    ];

    for (const testCase of testCases) {
        console.log(`[TEST CASE] Expecting: ${testCase.expected}`);
        await testFileAction(testCase.file, testCase.tool, testCase.destination);
        console.log('');
    }

    console.log('Evaluation test run completed.');
}

if (require.main === module) {
    runTestSuite();
}

module.exports = {
    testFileAction,
    runTestSuite
};
