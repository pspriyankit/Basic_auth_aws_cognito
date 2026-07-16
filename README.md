# ChatUI Cognito Login Project

## Architecture

User opens:

https://chatui.org

Flow:

1. Cloudflare receives HTTPS request
2. Cloudflare forwards HTTP request to EC2 because SSL mode is Flexible
3. Nginx receives request on port 80
4. Nginx proxies request to Node.js on 127.0.0.1:3000
5. Express checks session
6. If no session, user is redirected to /login
7. /login redirects user to AWS Cognito Hosted UI
8. Cognito handles signup/login/email verification
9. Cognito redirects back to /callback with authorization code
10. Express exchanges code for tokens at Cognito /oauth2/token
11. Express verifies ID token using Cognito public keys
12. Express stores verified user in session
13. User sees welcome page
14. /api/me proves backend API protection
15. /logout clears Express session and Cognito session

## Important files

Application:

server.js

Environment:

.env

Nginx config:

/etc/nginx/sites-available/chatui.org

PM2 process:

chatui-cognito

## Useful commands

Start app manually:

node server.js

PM2 status:

pm2 status

Restart app:

pm2 restart chatui-cognito

View logs:

pm2 logs chatui-cognito

Test Nginx:

sudo nginx -t

Reload Nginx:

sudo systemctl reload nginx

## Cognito config

Region:

ap-south-1

Callback URL:

https://chatui.org/callback

Sign-out URL:

https://chatui.org

Scopes used:

openid
email

OAuth grant type:

Authorization code grant

## Key learning

Client secret authenticates the backend app to Cognito.

Cognito signs JWT tokens using Cognito's private key.

Our app verifies JWT tokens using Cognito's public keys.

Browser stores a session cookie.

Server stores authenticated user in session.

Protected pages and APIs check req.session.user.
