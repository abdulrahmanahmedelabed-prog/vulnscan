import { NextResponse } from 'next/server';

export async function GET(request: Request, { params }: { params: { id: string } }) {
  const { searchParams } = new URL(request.url);
  const target = searchParams.get('callback');
  const upstream = await fetch(target);
  return NextResponse.json({ id: params.id, status: upstream.status });
}

export async function PUT(request: Request) {
  const body = await request.json();
  return NextResponse.json(body);
}
