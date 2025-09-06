# DNS Setup Instructions for kybershield.io on Hostinger

## Step 1: Deploy on Replit

1. In your Replit workspace, click the **Deploy** button
2. Choose **Autoscale** deployment type
3. Click **Deploy** to create your deployment

## Step 2: Get DNS Records from Replit

1. After deployment, go to **Deployments** tab
2. Click on **Settings**
3. Find **Domain Linking** section
4. Click **"Add Domain"** or **"Manually connect from another registrar"**
5. Enter: `kybershield.io` (without www)
6. Replit will show you:
   - An **A record** IP address (like `34.132.134.162`)
   - A **TXT record** verification string

Also add `www.kybershield.io`:
1. Click **"Add Domain"** again
2. Enter: `www.kybershield.io`
3. Note the same IP and TXT record

## Step 3: Configure DNS in Hostinger

1. Log into your **Hostinger hPanel**
2. Go to **Websites** → **Dashboard**
3. Click **Advanced** → **DNS Zone Editor**

### Add these DNS records:

#### For root domain (kybershield.io):
- **Type**: A Record
- **Name**: @ (or leave blank)
- **Points to**: [IP from Replit]
- **TTL**: 14400

- **Type**: TXT Record
- **Name**: @ (or leave blank)
- **TXT Value**: [Verification string from Replit]
- **TTL**: 14400

#### For www subdomain:
- **Type**: A Record
- **Name**: www
- **Points to**: [Same IP from Replit]
- **TTL**: 14400

- **Type**: TXT Record
- **Name**: www
- **TXT Value**: [Same verification string from Replit]
- **TTL**: 14400

### Remove conflicting records:
- Delete any existing CNAME records for @ or www
- Delete any other A records that conflict

## Step 4: Verify Domain Connection

1. Go back to Replit **Deployments** → **Settings**
2. Your domains should show **"Verifying..."** status
3. Wait 5-30 minutes for DNS propagation
4. Status will change to **"Verified"** when ready
5. SSL certificates will be automatically provisioned

## Step 5: Test Your Domain

Once verified, your site will be accessible at:
- https://kybershield.io
- https://www.kybershield.io

## Troubleshooting

If domain doesn't verify after 1 hour:
1. Check DNS propagation: https://dnschecker.org
2. Ensure no proxy/CDN is enabled (like Cloudflare orange cloud)
3. Verify records are exactly as Replit provided
4. Check Hostinger nameservers are active

## Important Notes

- Replit automatically handles SSL certificates
- Both HTTP and HTTPS will work (HTTP redirects to HTTPS)
- The deployment will auto-scale based on traffic
- Monitor deployment health in Replit dashboard