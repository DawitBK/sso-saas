/**
 * The readable part of a group's distinguished name: `CN=Reception,OU=Groups,DC=...` is "Reception".
 * Kept out of the page files because a Next page may export only its default component.
 */
export function groupName(dn: string): string {
  const cn = /^CN=((?:\\.|[^,\\])+)/i.exec(dn)?.[1];
  return cn ? cn.replace(/\\(.)/g, '$1') : dn;
}
