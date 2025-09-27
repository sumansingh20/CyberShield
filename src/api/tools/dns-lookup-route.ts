import { NextRequest } from 'next/server';

export const dynamic = "force-static";
export const revalidate = 0;

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const domain = searchParams.get('domain');

  if (!domain || typeof domain !== 'string') {
    return Response.json({ error: 'Missing domain parameter' }, { status: 400 });
  }

  try {
    // Fetch A records
    const ipv4Response = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
    const ipv4Data = await ipv4Response.json();
    
    // Fetch AAAA records
    const ipv6Response = await fetch(`https://dns.google/resolve?name=${domain}&type=AAAA`);
    const ipv6Data = await ipv6Response.json();

    const ipv4Addresses = ipv4Data.Answer?.map((record: any) => record.data) || [];
    const ipv6Addresses = ipv6Data.Answer?.map((record: any) => record.data) || [];

    return Response.json({
      domain: domain,
      ipv4: ipv4Addresses,
      ipv6: ipv6Addresses
    });

  } catch (error) {
    console.error('DNS lookup error:', error);
    return Response.json(
      { error: 'DNS lookup failed' }, 
      { status: 500 }
    );
  }
}
