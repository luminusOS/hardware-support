import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const workflow = new URL('../workflows/oidc-claim-probe.yml', import.meta.url);
const fields = [
  'repository_id', 'repository_owner_id', 'repository', 'repository_owner',
  'ref', 'sha', 'workflow_ref', 'workflow_sha', 'job_workflow_ref',
  'job_workflow_sha', 'sub', 'runner_environment', 'event_name',
  'run_id', 'run_attempt',
];
const claims = Object.fromEntries(fields.map(field => [field, `${field}:value`]));

function run({ payload = claims, url = 'https://probe.actions.githubusercontent.com/token', status = 200 } = {}) {
  const script = readFileSync(workflow, 'utf8')
    .split("node --input-type=module <<'NODE'\n")[1]
    .split('\n          NODE\n')[0];
  const jwt = `header.${Buffer.from(JSON.stringify({ ...payload, jti: 'do-not-report-jti' })).toString('base64url')}.signature`;
  const mock = `
    globalThis.fetch = async (url, options) => {
      process.stderr.write('fixture-fetch-called\\n');
      if (url.origin !== 'https://probe.actions.githubusercontent.com' ||
          url.searchParams.get('audience') !== 'luminusos-hardware-oidc-inert-probe' ||
          options.headers.Authorization !== 'Bearer fixture-request-credential' ||
          options.redirect !== 'error') {
        throw new Error('unexpected request');
      }
      return { ok: ${status === 200}, json: async () => ({ value: ${JSON.stringify(jwt)} }) };
    };
  `;
  return spawnSync(process.execPath, ['--input-type=module'], {
    input: mock + script,
    encoding: 'utf8',
    env: { ACTIONS_ID_TOKEN_REQUEST_URL: url, ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'fixture-request-credential' },
  });
}

test('reports only the selected claims, never credentials or unrelated claims', () => {
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), claims);
  assert.doesNotMatch(result.stdout + result.stderr, /fixture-request-credential|do-not-report-jti|header\./);
});

test('reports explicit absence and fails when a same-job workflow claim is missing', () => {
  const result = run({ payload: { ...claims, job_workflow_ref: undefined } });
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).job_workflow_ref, null);
});

test('refuses an unexpected destination before calling fetch', () => {
  const result = run({ url: 'https://probe.actions.githubusercontent.com.example.org/token' });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.doesNotMatch(result.stderr, /fixture-fetch-called|fixture-request-credential|do-not-report-jti|header\./);
});

test('never prints a failed HTTP response or any credentials', () => {
  const result = run({ status: 403 });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /fixture-fetch-called/);
  assert.doesNotMatch(result.stderr, /fixture-request-credential|do-not-report-jti|header\./);
});
