const test = require('node:test');
const assert = require('node:assert/strict');
const { configuration, isLoopback, proxyAI } = require('../ai-provider');

test('local AI proxy accepts loopback URLs only', () => {
  const previous = process.env.GHOSTGUARD_AI_URL;
  process.env.GHOSTGUARD_AI_URL = 'http://127.0.0.1:8001';
  assert.equal(configuration().enabled, true);
  process.env.GHOSTGUARD_AI_URL = 'https://example.com';
  assert.equal(configuration().enabled, false);
  if (previous === undefined) delete process.env.GHOSTGUARD_AI_URL;
  else process.env.GHOSTGUARD_AI_URL = previous;
});

test('loopback origin checks reject non-local hosts', () => {
  assert.equal(isLoopback('localhost'), true);
  assert.equal(isLoopback('127.0.0.1'), true);
  assert.equal(isLoopback('::1'), true);
  assert.equal(isLoopback('example.com'), false);
});

test('local AI proxy only permits explicit backend routes', async () => {
  await assert.rejects(proxyAI('api/chat', {}), /not allowed/);
});
