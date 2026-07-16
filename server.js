require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const { CognitoJwtVerifier } = require("aws-jwt-verify");

const app = express();

const {
  PORT,
  COGNITO_USER_POOL_ID,
  COGNITO_CLIENT_ID,
  COGNITO_CLIENT_SECRET,
  COGNITO_DOMAIN,
  COGNITO_REDIRECT_URI,
  COGNITO_LOGOUT_URI,
  SESSION_SECRET
} = process.env;


/*
|--------------------------------------------------------------------------
| Check required environment variables
|--------------------------------------------------------------------------
*/

const requiredVariables = [
  "COGNITO_USER_POOL_ID",
  "COGNITO_CLIENT_ID",
  "COGNITO_CLIENT_SECRET",
  "COGNITO_DOMAIN",
  "COGNITO_REDIRECT_URI",
  "COGNITO_LOGOUT_URI",
  "SESSION_SECRET"
];

for (const variable of requiredVariables) {
  if (!process.env[variable]) {
    throw new Error(`Missing environment variable: ${variable}`);
  }
}


/*
|--------------------------------------------------------------------------
| Express configuration
|--------------------------------------------------------------------------
*/

// We will later place Express behind Nginx and Cloudflare.
app.set("trust proxy", 1);

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 60 * 60 * 1000
    }
  })
);


/*
|--------------------------------------------------------------------------
| Cognito ID-token verifier
|--------------------------------------------------------------------------
*/

const idTokenVerifier = CognitoJwtVerifier.create({
  userPoolId: COGNITO_USER_POOL_ID,
  tokenUse: "id",
  clientId: COGNITO_CLIENT_ID
});


/*
|--------------------------------------------------------------------------
| Home page
|--------------------------------------------------------------------------
*/

app.get("/", (req, res) => {

  // If no authenticated user exists in the session,
  // send the user to Cognito login.
  if (!req.session.user) {
    return res.redirect("/login");
  }

  const username =
    req.session.user.name ||
    req.session.user.email ||
    req.session.user["cognito:username"] ||
    "User";

  res.send(`
    <!DOCTYPE html>

    <html lang="en">

    <head>

      <meta charset="UTF-8">

      <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
      >

      <title>ChatUI</title>

      <style>

        * {
          box-sizing: border-box;
        }

        body {
          min-height: 100vh;
          margin: 0;

          display: flex;
          align-items: center;
          justify-content: center;

          font-family: Arial, sans-serif;

          background:
            linear-gradient(
              135deg,
              #101828,
              #253b80
            );

          color: white;
        }

        .card {
          width: 90%;
          max-width: 550px;

          padding: 55px 40px;

          text-align: center;

          border-radius: 22px;

          background:
            rgba(
              255,
              255,
              255,
              0.1
            );

          border:
            1px solid
            rgba(
              255,
              255,
              255,
              0.2
            );

          box-shadow:
            0 25px 60px
            rgba(
              0,
              0,
              0,
              0.3
            );
        }

        h1 {
          margin-top: 0;
          font-size: 38px;
        }

        p {
          opacity: 0.85;
          line-height: 1.6;
        }

        a {
          display: inline-block;

          margin-top: 25px;

          padding: 13px 30px;

          border-radius: 9px;

          background: white;

          color: #172554;

          text-decoration: none;

          font-weight: bold;
        }

      </style>

    </head>

    <body>

      <main class="card">

        <h1>
          Welcome, ${escapeHtml(username)} 👋
        </h1>

        <p>
          You successfully signed in using
          Amazon Cognito.
        </p>

        <a href="/logout">
          Sign Out
        </a>

      </main>

    </body>

    </html>
  `);
});


/*
|--------------------------------------------------------------------------
| Send the user to Cognito
|--------------------------------------------------------------------------
*/

app.get("/login", (req, res) => {

  // State protects the OAuth flow against
  // forged callback requests.
  const state = crypto
    .randomBytes(32)
    .toString("hex");

  req.session.oauthState = state;

  const parameters = new URLSearchParams({

    response_type: "code",

    client_id:
      COGNITO_CLIENT_ID,

    redirect_uri:
      COGNITO_REDIRECT_URI,

    scope:
      "openid email",

    state
  });

  const loginUrl =
    `${COGNITO_DOMAIN}` +
    `/oauth2/authorize?` +
    parameters.toString();

  res.redirect(loginUrl);
});


/*
|--------------------------------------------------------------------------
| Cognito callback
|--------------------------------------------------------------------------
*/

app.get("/callback", async (req, res) => {

  try {

    const {
      code,
      state,
      error,
      error_description
    } = req.query;


    /*
    | Cognito returned a login error
    */

    if (error) {

      return res
        .status(400)
        .send(
          `
          <h1>Login failed</h1>

          <p>
            ${escapeHtml(
              error_description || error
            )}
          </p>
          `
        );
    }


    /*
    | Verify OAuth state
    */

    if (
      !state ||
      state !== req.session.oauthState
    ) {

      return res
        .status(400)
        .send(
          "Invalid OAuth state."
        );
    }


    /*
    | Ensure Cognito returned a code
    */

    if (!code) {

      return res
        .status(400)
        .send(
          "Authorization code was not received."
        );
    }


    /*
    | Prepare token request
    */

    const tokenRequestBody =
      new URLSearchParams({

        grant_type:
          "authorization_code",

        client_id:
          COGNITO_CLIENT_ID,

        code,

        redirect_uri:
          COGNITO_REDIRECT_URI
      });


    /*
    | Authenticate the backend app
    | using client ID and client secret
    */

    const clientCredentials =
      Buffer
        .from(
          `${COGNITO_CLIENT_ID}:` +
          `${COGNITO_CLIENT_SECRET}`
        )
        .toString("base64");


    /*
    | Exchange authorization code
    | for Cognito tokens
    */

    const tokenResponse =
      await fetch(

        `${COGNITO_DOMAIN}/oauth2/token`,

        {

          method: "POST",

          headers: {

            "Content-Type":
              "application/x-www-form-urlencoded",

            Authorization:
              `Basic ${clientCredentials}`
          },

          body:
            tokenRequestBody.toString()
        }
      );


    const tokens =
      await tokenResponse.json();


    if (!tokenResponse.ok) {

      console.error(
        "Cognito token error:",
        tokens
      );

      return res
        .status(400)
        .json(tokens);
    }


    /*
    | Verify the ID token
    */

    const user =
      await idTokenVerifier.verify(
        tokens.id_token
      );


    /*
    | Store user details in session
    */

    req.session.user = user;

    req.session.tokens = {

      accessToken:
        tokens.access_token,

      idToken:
        tokens.id_token,

      refreshToken:
        tokens.refresh_token
    };


    delete req.session.oauthState;


    /*
    | Return user to home page
    */

    res.redirect("/");

  }

  catch (error) {

    console.error(
      "Authentication error:",
      error
    );

    res
      .status(500)
      .send(
        "Authentication failed."
      );
  }

});

/*
|--------------------------------------------------------------------------
| Protected API route
|--------------------------------------------------------------------------
*/

app.get("/api/me", (req, res) => {

  if (!req.session.user) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Please login first."
    });
  }

  res.json({
    message: "You are authenticated.",
    user: {
      name:
        req.session.user.name || null,

      email:
        req.session.user.email || null,

      username:
        req.session.user["cognito:username"] || null,

      subject:
        req.session.user.sub || null
    }
  });

});

/*
|--------------------------------------------------------------------------
| Logout
|--------------------------------------------------------------------------
*/

app.get("/logout", (req, res) => {

  req.session.destroy(() => {

    const parameters =
      new URLSearchParams({

        client_id:
          COGNITO_CLIENT_ID,

        logout_uri:
          COGNITO_LOGOUT_URI
      });


    const logoutUrl =
      `${COGNITO_DOMAIN}` +
      `/logout?` +
      parameters.toString();


    res.redirect(logoutUrl);

  });

});

/*
|--------------------------------------------------------------------------
| Escape values before placing them in HTML
|--------------------------------------------------------------------------
*/

function escapeHtml(value) {

  return String(value)

    .replaceAll(
      "&",
      "&amp;"
    )

    .replaceAll(
      "<",
      "&lt;"
    )

    .replaceAll(
      ">",
      "&gt;"
    )

    .replaceAll(
      '"',
      "&quot;"
    )

    .replaceAll(
      "'",
      "&#039;"
    );
}


/*
|--------------------------------------------------------------------------
| Start application
|--------------------------------------------------------------------------
*/

app.listen(

  PORT || 3000,

  "127.0.0.1",

  () => {

    console.log(
      `ChatUI running on ` +
      `http://127.0.0.1:` +
      `${PORT || 3000}`
    );

  }

);
