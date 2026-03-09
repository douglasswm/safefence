/**
 * Catch-all proxy route — forwards requests to the control plane API.
 * Avoids CORS issues by keeping browser→dashboard on the same origin.
 */

import { NextRequest, NextResponse } from "next/server";

const CONTROL_PLANE_URL =
  process.env.CONTROL_PLANE_URL ?? "http://localhost:3100";

async function proxyRequest(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  // Auth gate: reject unauthenticated requests
  const auth = request.headers.get("Authorization");
  if (!auth) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { path } = await params;
  // Sanitize path: filter traversal segments and encode each segment
  const safePath = path
    .filter((seg) => seg !== ".." && seg !== ".")
    .map((seg) => encodeURIComponent(seg))
    .join("/");
  const upstream = `${CONTROL_PLANE_URL}/api/v1/${safePath}${request.nextUrl.search}`;

  const headers: Record<string, string> = {};
  const contentType = request.headers.get("Content-Type");
  if (contentType) headers["Content-Type"] = contentType;
  headers["Authorization"] = auth;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10_000);

  const init: RequestInit = {
    method: request.method,
    headers,
    signal: controller.signal,
  };

  if (request.method !== "GET" && request.method !== "HEAD") {
    try {
      init.body = await request.text();
    } catch {
      // no body
    }
  }

  try {
    const upstream_res = await fetch(upstream, init);
    clearTimeout(timeoutId);

    return new NextResponse(upstream_res.body, {
      status: upstream_res.status,
      headers: {
        "Content-Type": upstream_res.headers.get("Content-Type") ?? "application/json",
      },
    });
  } catch (err) {
    clearTimeout(timeoutId);
    const isTimeout = err instanceof Error && err.name === "AbortError";
    return NextResponse.json(
      { error: isTimeout ? "Control plane request timed out" : "Control plane unreachable" },
      { status: isTimeout ? 504 : 502 },
    );
  }
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const DELETE = proxyRequest;
export const PATCH = proxyRequest;
