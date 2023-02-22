/*
Usage

Start: 
npm run start
Go to http://localhost:3001/authentication -> redirect to sign page from server -> authorize -> Strategy
// http://localhost:3001/authentication2
*/

import express, { Express } from "express";
import cors from "cors";
import expressSession from "express-session";
import { Issuer, Strategy, TokenSet } from "./lib/index.js";
import passport from "passport";
// import { create as createRootCas } from "ssl-root-cas";

const local = true;
let autoIssuerUrl;
let clientId;
let clientSecret;
let rejectNewUsers;
if (local) {
  autoIssuerUrl = "http://localhost:5770/.well-known/openid-configuration";
  clientId = "oidcCLIENT";
  clientSecret = "verysecret";
  rejectNewUsers = false;
} else {
  autoIssuerUrl = "";
  clientId = "KILI";
  clientSecret = "";
  rejectNewUsers = false;
}

// const rootCas = createRootCas();
// rootCas.addFile("./ssl/rca.pem");

export const IS_USING_OPENID_CONNECT = !!autoIssuerUrl;

export const fullPath = (route: string) => `${route}`;

export enum AuthRoute {
  AuthenticationStart = "/authentication",
  AuthenticationCallback = "/authentication/callback",
  LogOutStart = "/logout",
  LogOutCallback = "/logout/callback",
  SignIn = "/signin",
}

const redirectURI = `http://localhost:3001${AuthRoute.AuthenticationCallback}`;

const getFrontendEndpoint = () => "http://localhost:3000";

async function init() {
  const app = express();
  const port = 3001;

  app.listen(port, () => {
    return console.log(`Express is listening at http://localhost:${port}`);
  });

  app.use(
    expressSession({
      cookie: {
        maxAge: 15 * 60 * 1000, // 15 minutes
      },
      resave: false,
      saveUninitialized: true,
      // secret: process.env.DATABASE__SESSION_SECRET ?? "",
      secret: "xxx",
    })
  );

  await openIdConnectStrategy(app);
}

const openIdConnectStrategy = async (app: Express) => {
  if (!IS_USING_OPENID_CONNECT) {
    return;
  }
  try {
    const issuer = await Issuer.discover(autoIssuerUrl);
    console.log(`To authenticate, go to http://localhost:3001/authentication`);
    // @ts-ignore
    const client = new issuer.Client({
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: [redirectURI],
      response_types: ["code"],
      token_endpoint_auth_method: clientSecret ? "client_secret_basic" : "none",
    });

    app.use(passport.initialize());
    app.use(passport.session());

    passport.use(
      "oidc",
      new Strategy(
        // @ts-ignore
        { client },
        // @ts-ignore
        async (tokenSet: TokenSet, userInfo: any, done: any) => {
          console.log("VERIFY", JSON.stringify({ tokenSet, userInfo }));
          if (!rejectNewUsers) {
            const email = userInfo.email;
            return done(null, userInfo);
          } else {
            return done(null, tokenSet.claims());
          }
        }
      )
    );

    app.get(fullPath(AuthRoute.AuthenticationStart), (req, res, next) => {
      // const scope = (issuer.metadata?.scopes_supported as string[]).join(' ') ?? 'openid email';
      console.log("START");
      const scope = "openid";
      // const scope = "openid";
      console.log({ scope });
      passport.authenticate("oidc", { scope })(req, res, next);
    });

    app.get(fullPath(AuthRoute.AuthenticationCallback), (req, res, next) => {
      console.log("CALLBACK");
      passport.authenticate("oidc", {
        failureRedirect: getFrontendEndpoint(),
        scope: "openid",
        successRedirect: `${getFrontendEndpoint()}/label/login/success`,
      })(req, res, next);
    });

    const corsOptions = {
      credentials: true,
      origin: true,
    };

    app.get(fullPath(AuthRoute.SignIn), cors(corsOptions), async (req, res) => {
      // @ts-ignore
      if (!req.isAuthenticated()) {
        res.redirect(getFrontendEndpoint());
      }
      // @ts-ignore
      const email = req.user?.email as string;
      // @ts-ignore
      console.log("USE SIGNIN", req.user);
      const user = await findByEmail(email);
      if (!user && rejectNewUsers) {
        return res.sendStatus(403);
      }
      const payload = {
        id: user.id,
        token: await createToken(user, "4w"),
        user,
      };
      return res.json(payload);
    });

    app.get(fullPath(AuthRoute.LogOutStart), (_, res) => {
      res.redirect(client.endSessionUrl());
    });

    app.get(fullPath(AuthRoute.LogOutCallback), (req, res) => {
      // @ts-ignore
      req.logout();
      res.redirect(getFrontendEndpoint());
    });

    passport.serializeUser((user: any, done: any) => {
      console.log("searialize", { user });
      done(null, user);
    });

    passport.deserializeUser((user: any, done: any) => {
      console.log("desearialize", { user });
      done(null, user);
    });
  } catch (error) {
    console.error("OpenId - failed to initialize connection with IDP");
    console.error(error);
    if (error instanceof Error) {
      console.error(error.stack);
    }
    throw error;
  }
};

const createToken = async (user, way) => {
  return "xxx";
};

const findByEmail = async (email) => {
  console.log("find by email");
  return {
    id: "xxx",
  };
};

init();
