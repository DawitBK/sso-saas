import { newPasswordProblem } from '../src/auth/password-policy.js';

describe('newPasswordProblem', () => {
  it('accepts an ordinary acceptable password, including the generic seed one', () => {
    expect(newPasswordProblem('Pass1234!', 'someone@examplecorp.net')).toBeNull();
    expect(newPasswordProblem('correct-horse-battery', 'x@y.z')).toBeNull();
  });
  it('refuses short, common, repeated and name-containing passwords', () => {
    expect(newPasswordProblem('short')).toMatch(/at least 8/);
    expect(newPasswordProblem('Password123')).toMatch(/common/);
    expect(newPasswordProblem('12345678')).toMatch(/common/);
    expect(newPasswordProblem('aaaaaaaaaa')).toMatch(/repeated/);
    expect(newPasswordProblem('daniel.bayer2026', 'daniel.bayer@examplecorp.net')).toMatch(/sign-in name/);
  });
});
