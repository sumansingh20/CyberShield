import dns from 'dns';
import { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const domain = searchParams.get('domain');

  if (!domain || typeof domain !== 'string') {
    return Response.json({ error: 'Missing domain parameter' }, { status: 400 });
  }

  try {
    // Perform DNS lookup for IPv4 addresses
    const ipv4Addresses = await new Promise<string[]>((resolve, reject) => {
      dns.resolve(domain, 'A', (err, addresses) => {
        if (err && err.code !== 'ENODATA' && err.code !== 'ENOTFOUND') {
          reject(err);
        } else {
          resolve(addresses || []);
        }
      });
    });

    // Perform DNS lookup for IPv6 addresses
    const ipv6Addresses = await new Promise<string[]>((resolve, reject) => {
      dns.resolve(domain, 'AAAA', (err, addresses) => {
        if (err && err.code !== 'ENODATA' && err.code !== 'ENOTFOUND') {
          reject(err);
        } else {
          resolve(addresses || []);
        }
      });
    });

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
