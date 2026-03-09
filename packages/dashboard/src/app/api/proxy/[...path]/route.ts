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
  const { path } = await params;
  const upstream = `${CONTROL_PLANE_URL}/api/v1/${path.join("/")}${request.nextUrl.search}`;

  const headers: Record<string, string> = {};
  const contentType = request.headers.get("Content-Type");
  if (contentType) headers["Content-Type"] = contentType;
  const auth = request.headers.get("Authorization");
  if (auth) headers["Authorization"] = auth;

  const init: RequestInit = {
    method: request.method,
    headers,
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

    return new NextResponse(upstream_res.body, {
      status: upstream_res.status,
      headers: {
        "Content-Type": upstream_res.headers.get("Content-Type") ?? "application/json",
      },
    });
  } catch (err) {
    return NextResponse.json(
      { error: "Control plane unreachable", detail: String(err) },
      { status: 502 },
    );
  }
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const DELETE = proxyRequest;
export const PATCH = proxyRequest;
