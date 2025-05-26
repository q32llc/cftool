# cftool

A command-line tool for migrating DNS configurations from legacy providers to Cloudflare, including DNS records, email forwarding, and URL redirects.

## Features

- Export DNS configurations from legacy providers (Namecheap, Name.com) to YAML
- Apply YAML configurations to Cloudflare
- Supports:
  - DNS records
  - Email forwarding rules
  - URL redirects
  - Nameserver updates
  - Cache bypass rules

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cftool.git
cd cftool

# Install dependencies using Poetry
poetry install
```

## Configuration

Create a `.env` file with the following variables:

```env
# Cloudflare
CF_API_TOKEN=your_cloudflare_api_token

# Namecheap (if using)
NC_API_USER=your_namecheap_api_user
NC_API_KEY=your_namecheap_api_key
NC_USERNAME=your_namecheap_username
NC_API_IP=your_ip_address

# Name.com (if using)
NAMEDOTCOM_USER=your_name.com_username
NAMEDOTCOM_TOKEN=your_name.com_api_token
```

## Usage

### Export Configuration

Export DNS configuration from legacy providers to YAML:

```bash
python -m cftool export domain1.com domain2.com > config.yml
```

### Apply Configuration

Apply the exported configuration to Cloudflare:

```bash
python -m cftool apply config.yml
```

For a dry run (no changes):

```bash
python -m cftool apply config.yml --dry
```

## YAML Configuration Format

```yaml
domains:
  example.com:
    dns_provider: namecheap  # or name.com
    origin: origin.example.com  # optional
    cache_bypass:  # optional
      - /api/*
      - /static/*
    records:  # DNS records
      - type: A
        name: @
        content: 1.2.3.4
        ttl: 3600
        proxied: true
    mail_forwarding:  # Email forwarding rules
      - from: info@example.com
        to: user@gmail.com
    url_redirects:  # URL redirects
      - source: https://old.example.com
        destination: https://new.example.com
        code: 301
    inject_csp: true  # Optional: Enable CSP header to prevent iframing
```

## Development

- Python 3.12+
- Poetry for dependency management
- Uses async/await for API calls
- Rich for terminal output

## Environment Variables

- `NC_API_USER`: Namecheap API username
- `NC_API_KEY`: Namecheap API key
- `NAMEDOTCOM_USER`: Name.com API username
- `NAMEDOTCOM_TOKEN`: Name.com API token
- `MAILGUN_API_KEY`: Mailgun API key (optional, for fetching Mailgun DNS records)

## License

MIT
