import { IDP_CONFIG } from '../src/config.js';
import { APP_REGISTRY, catalog } from '../src/portal/catalog.js';
import { APPS } from '../src/admin/access.js';

describe('one list of launcher systems', () => {
  it('the console APPS list is the registry (rp and label), so a tile can always be entitled', () => {
    expect(APPS).toEqual(APP_REGISTRY.map((a) => ({ rp: a.rp, label: a.label })));
    expect(APPS.map((a) => a.rp)).toEqual(expect.arrayContaining(['edams', 'gms']));
  });

  it('every registry entry matches a registered OIDC client or the GMS bridge', () => {
    const clients = IDP_CONFIG.clientSeed.map((c) => c.client_id);
    for (const a of APP_REGISTRY) expect(clients).toContain(a.rp);
  });

  it('enabled gates the tile only, not the entitlement list', () => {
    const saved = IDP_CONFIG.gms.enabled;
    (IDP_CONFIG.gms as { enabled: boolean }).enabled = false;
    try {
      expect(catalog().map((t) => t.rp)).not.toContain('gms');
      expect(APPS.map((a) => a.rp)).toContain('gms');
    } finally {
      (IDP_CONFIG.gms as { enabled: boolean }).enabled = saved;
    }
  });
});
