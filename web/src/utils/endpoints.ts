/** Builds an absolute URL on the origin serving the SPA and protocol routes. */
export function protocolUrl(path: string, origin = window.location.origin): string {
  return new URL(path, origin).toString();
}
