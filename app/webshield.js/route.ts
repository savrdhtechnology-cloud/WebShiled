import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const SCRIPT = String.raw`(() => {
  try {
    const script = document.currentScript;
    const siteKey = script && script.getAttribute("data-site-key");
    if (!siteKey) return;

    const endpoint = "https://webshield-savrdh-technology.vercel.app/api/collect";
    const storageKey = "webshield:visitor:" + siteKey;
    let visitorKey = "";
    try {
      visitorKey = sessionStorage.getItem(storageKey) || "";
      if (!visitorKey) {
        visitorKey = (globalThis.crypto && crypto.randomUUID)
          ? crypto.randomUUID()
          : Date.now().toString(36) + Math.random().toString(36).slice(2);
        sessionStorage.setItem(storageKey, visitorKey);
      }
    } catch {
      visitorKey = Date.now().toString(36) + Math.random().toString(36).slice(2);
    }

    let lastUrl = "";
    const send = () => {
      const url = location.href;
      if (url === lastUrl) return;
      lastUrl = url;
      fetch(endpoint, {
        method: "POST",
        mode: "cors",
        credentials: "omit",
        keepalive: true,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          siteKey,
          url,
          referrer: document.referrer || "",
          visitorKey,
          webdriver: Boolean(navigator.webdriver)
        })
      }).catch(() => {});
    };

    send();

    const wrapHistory = (name) => {
      const original = history[name];
      if (typeof original !== "function") return;
      history[name] = function () {
        const result = original.apply(this, arguments);
        setTimeout(send, 0);
        return result;
      };
    };
    wrapHistory("pushState");
    wrapHistory("replaceState");
    addEventListener("popstate", send);
    addEventListener("hashchange", send);
  } catch {}
})();`;

export async function GET() {
  return new NextResponse(SCRIPT, {
    status: 200,
    headers: {
      "content-type": "application/javascript; charset=utf-8",
      "cache-control": "public, max-age=300, s-maxage=300",
      "x-content-type-options": "nosniff"
    }
  });
}
