# Vireon Group — Independent Website & Admin Platform

This is a separate project. It does not connect to or modify MountPeak Group.

## Included
- Responsive corporate website using the supplied Vireon logo and approved ivory/gold architectural visual direction.
- Home, About, Businesses, Expertise, Leadership and Contact sections.
- Leadership display: Vinay Mishra — Chief Patron; Vivek Mishra — Founder & CEO.
- Contact enquiry endpoint.
- Separate admin login, client records, invoices with PDF generation, income/expense entries, enquiry viewing and activity logs.
- No payment gateway and no public domain configured.

## Run locally
1. Install Node.js 20 or later.
2. Copy `.env.example` to `.env`.
3. Set a unique random `JWT_SECRET` (at least 32 characters), `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD`.
4. In the project folder run `npm install`.
5. Run `npm start`.
6. Open `http://localhost:3000`; admin is at `http://localhost:3000/admin`.

The SQLite database is created automatically as `vireon.sqlite`. Keep `.env` and the database private. Back up the database regularly.

## Before public deployment
- Configure HTTPS and a persistent disk for `vireon.sqlite`.
- Set production secrets in the hosting provider, never commit `.env`.
- Add privacy/terms pages and verify the legal business details and contact details.
- Review the proposed business-area copy so it accurately describes actual operations.
- Use a managed database or reliable persistent storage and scheduled backups before relying on this for financial records.
- The leadership titles shown on the public site are presentation labels; they do not change the sole-proprietorship legal structure.
- No domain is required for local testing or initial hosting setup.

## Notes
The sample site intentionally avoids unsupported claims such as employee counts, countries served, project value, client logos or revenue figures. Replace/add factual company details only when confirmed.
