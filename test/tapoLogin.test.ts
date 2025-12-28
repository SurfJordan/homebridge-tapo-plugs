import { createLoginByIp } from '../src/tapo/login.js';

describe('createLoginByIp', () => {
  it('uses KLAP login when it succeeds', async () => {
    const loginKlap = jest.fn().mockResolvedValue({ session: 'klap' });
    const loginLegacy = jest.fn();
    const login = createLoginByIp(loginKlap, loginLegacy);

    const session = await login('user@example.com', 'password', '192.168.1.10');

    expect(session).toEqual({ session: 'klap' });
    expect(loginLegacy).not.toHaveBeenCalled();
  });

  it('falls back to legacy when KLAP is unsupported', async () => {
    const loginKlap = jest.fn().mockRejectedValue(new Error('Klap protocol not supported'));
    const loginLegacy = jest.fn().mockResolvedValue({ session: 'legacy' });
    const login = createLoginByIp(loginKlap, loginLegacy);

    const session = await login('user@example.com', 'password', '192.168.1.10');

    expect(session).toEqual({ session: 'legacy' });
    expect(loginLegacy).toHaveBeenCalledTimes(1);
  });

  it('does not fall back on other errors', async () => {
    const loginKlap = jest.fn().mockRejectedValue(new Error('email or password incorrect'));
    const loginLegacy = jest.fn();
    const login = createLoginByIp(loginKlap, loginLegacy);

    await expect(login('user@example.com', 'password', '192.168.1.10'))
      .rejects
      .toThrow('email or password incorrect');

    expect(loginLegacy).not.toHaveBeenCalled();
  });
});
