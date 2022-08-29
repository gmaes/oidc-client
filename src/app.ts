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
import { Issuer, Strategy, TokenSet } from "openid-client";
import passport from "passport";
import { create as createRootCas } from "ssl-root-cas";
import OpenIDConnectStrategy from "./strategy";

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

const rootCas = createRootCas();
rootCas.addFile("./ssl/rca.pem");

export const IS_USING_OPENID_CONNECT = !!autoIssuerUrl;

export const fullPath = (route: string) => `${route}`;

export enum AuthRoute {
  AuthenticationStart = "/authentication",
  AuthenticationCallback = "/authentication/callback",
  LogOutStart = "/logout",
  LogOutCallback = "/logout/callback",
  SignIn = "/signin",
}
export enum AuthRoute2 {
  AuthenticationStart = "/authentication2",
  AuthenticationCallback = "/authentication2/callback",
  LogOutStart = "/logout",
  LogOutCallback = "/logout/callback",
  SignIn = "/signin",
}

const redirectURI = `http://localhost:3001${AuthRoute.AuthenticationCallback}`;
const redirectURI2 = `http://localhost:3001${AuthRoute2.AuthenticationCallback}`;

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
    console.log(`To authenticate, go to http://localhost:3001/authentication2`);

    app.use(passport.initialize());
    app.use(passport.session());

    passport.serializeUser((user: any, done: any) => {
      console.log("searialize", { user });
      done(null, user);
    });

    passport.deserializeUser((user: any, done: any) => {
      console.log("desearialize", { user });
      done(null, user);
    });

    const strategy = new OpenIDConnectStrategy(
      {
        issuer: "http://localhost:5770/",
        authorizationURL: "http://localhost:5770/auth",
        tokenURL: "http://localhost:5770/token",
        userInfoURL: "http://localhost:5770/me",
        clientID: clientId,
        clientSecret: clientSecret,
        callbackURL: redirectURI2,
      },
      // {
      //   issuer: "https://identityrec.devinfo.fr.cly/outil/SOID/",
      //   authorizationURL:
      //     "https://identityrec.devinfo.fr.cly/outil/SOID/openid/authorize",
      //   tokenURL: "https://identityrec.devinfo.fr.cly/outil/SOID/openid/token",
      //   userInfoURL:
      //     "https://identityrec.devinfo.fr.cly/outil/SOID/openid/userinfo",
      //   clientID: clientId,
      //   clientSecret: clientSecret,
      //   callbackURL: redirectURI2,
      // },
      function verify(issuer, profile, cb) {
        console.log("VERIFY", { profile });
        const user = { email: "test+admin@kili-technology.com" };
        return cb(null, user);
      }
    );

    passport.use(strategy);

    app.get(
      fullPath(AuthRoute2.AuthenticationStart),
      passport.authenticate("openidconnect")
    );
    app.get(
      fullPath(AuthRoute2.AuthenticationCallback),
      passport.authenticate("openidconnect", {
        failureRedirect: "/login",
        failureMessage: true,
      }),
      function (req, res) {
        res.redirect("/");
      }
    );
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
