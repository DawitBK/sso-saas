'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';

interface Group {
  dn: string;
  memberCount: number;
}

interface GroupsData {
  groups: Group[];
}

export default function GroupsPage() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<GroupsData | null>(null);

  useEffect(() => {
    fetch(apiPath('/api/v1/admin/groups'))
      .then((res) => res.json())
      .then((json) => {
        setData(json.data ?? null);
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load groups');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!data) {
    return <div>Failed to load groups</div>;
  }

  return (
    <>
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: '20px', margin: '0 0 4px' }}>Groups</h1>
        <p className="sub" style={{ color: 'var(--muted)', fontSize: '13px', margin: '0' }}>
          Every group that has members, an app entitlement, or a role mapping anywhere in the system.
        </p>
      </div>

      <div className="admin-card">
        {data.groups.length === 0 ? (
          <p style={{ color: 'var(--muted)' }}>No groups yet — add a user to a group from their user page.</p>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Group</th>
                <th>Members</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.groups.map((group) => (
                <tr key={group.dn}>
                  <td>
                    <code className="admin-code">{group.dn}</code>
                  </td>
                  <td>{group.memberCount}</td>
                  <td style={{ textAlign: 'right' }}>
                    <Link href={`/admin/groups/detail?dn=${encodeURIComponent(group.dn)}`} className="admin-link">
                      Configure access →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
