export const BASE_PATH = "/webshield";

export function withBasePath(path: string) {
  if (!path) return BASE_PATH;
  if (/^https?:\/\//i.test(path)) return path;
  if (path.startsWith(BASE_PATH + "/") || path === BASE_PATH) return path;
  if (path.startsWith("#")) return BASE_PATH + "/" + path;
  return BASE_PATH + (path.startsWith("/") ? path : "/" + path);
}

export function apiPath(path: string) {
  return withBasePath(path.startsWith("/api/") ? path : "/api/" + path.replace(/^\//, ""));
}
